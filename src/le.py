#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:

#pylint: disable=wrong-import-order, wrong-import-position
from __future__ import absolute_import

from future.standard_library import install_aliases

install_aliases()
from urllib.parse import urlencode, quote #pylint: disable=import-error

import json
import atexit
import glob
import logging
import logging.handlers
import os
import os.path
import platform
import random
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import traceback
import requests
import queue
from queue import Queue
import http.client
# Do not remove - fix for Python #8484
try:
    import hashlib #pylint: disable=unused-import
except ImportError:
    pass
from logentries import formats as formats
from logentries import socks as socks
from logentries import utils as utils
from logentries import metrics as metrics
from logentries.config import Config, FatalConfigurationError
from logentries.followers import Follower, MultilogFollower
from logentries.log import log as log_object
from logentries.domain import Domain
from logentries.backports import CertificateError, match_hostname
from logentries.datetime_utils import parse_timestamp_range
from logentries.constants import * #pylint: disable=unused-wildcard-import, wildcard-import


# Explicitely set umask to allow user rw + group read
os.umask(stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)


CONFIG = Config()
LOG = log_object.log

def _debug_filters(msg, *args):
    """Print debug filters"""
    if CONFIG.debug_filters:
        sys.stderr.write(msg % args)


def _debug_formatters(msg, *args):
    """Print debug formatters"""
    if CONFIG.debug_formatters:
        sys.stderr.write(msg % args)



NO_SSL = False
FEAT_SSL = True
try:
    import ssl

    wrap_socket = ssl.wrap_socket #pylint: disable=invalid-name
    CERT_REQUIRED = ssl.CERT_REQUIRED
except ImportError:
    NO_SSL = True
    FEAT_SSL = False

    try:
        _ = http.client.HTTPSConnection
    except AttributeError:
        utils.die('NOTE: Please install Python "ssl" module.')

    CERT_REQUIRED = 0

#
# Custom proctitle
#


#
# User-defined filtering code
#
def filter_events(events):
    """
    User-defined filtering code. Events passed are about to be sent to
    logentries server. Make the required modifications to the events such
    as removing unwanted or sensitive information.
    """
    # By default, this method is empty
    return events


def default_filter_filenames(filename):#pylint: disable=unused-argument
    """
    By default we allow to follow any files specified in the configuration.
    """
    return True


def format_entries(default_formatter, entries):
    """
    User-defined formattering code. Events passed are about to be sent to
    logentries server. Make the required modifications to provide correct format.
    """
    # By default, this method is empty
    return default_formatter.format_line(entries)


def call(command):
    """
    Calls the given command in OS environment.
    """
    output = subprocess.Popen(
        command, stdout=subprocess.PIPE, shell=True).stdout.read()
    if len(output) == 0:
        return ''
    if output[-1] == '\n':
        output = output[:-1]
    return output


def _lock_pid_file_name():
    """
    Returns path to a file for protecting critical section
    for daemonizing (see daemonize() )
    """
    return CONFIG.pid_file + '.lock'


def _lock_pid():
    """
    Tries to exclusively open file for protecting of critical section
    for daemonizing.
    """
    file_name = _lock_pid_file_name()
    try:
        file_ = os.open(file_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except OSError:
        return None
    if file_ == -1:
        return None
    os.close(file_)
    return True


def _unlock_pid():
    """
    Releases file for protecting of critical section for daemonizing.
    """
    try:
        file_name = _lock_pid_file_name()
        os.remove(file_name)
    except OSError:
        pass


def _try_daemonize():
    """
    Creates a daemon from the current process.
    http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
    Alternative: python-daemon
    """

    try:
        pidfile = open(CONFIG.pid_file, 'r')
        pid = int(pidfile.read().strip())
        pidfile.close()
    except IOError:
        pid = None
    if pid:
        if not os.path.exists('/proc') or os.path.exists("/proc/%d/status" % pid):
            return "Pidfile %s already exists. Daemon already running?" % CONFIG.pid_file

    try:
        # Open pid file
        if CONFIG.pid_file:
            open(CONFIG.pid_file, 'w').close()

        pid = os.fork()
        if pid > 0:
            sys.exit(EXIT_OK)
        os.chdir("/")
        os.setsid()
        os.umask(0)
        pid = os.fork()
        if pid > 0:
            sys.exit(EXIT_OK)
        sys.stdout.flush()
        sys.stderr.flush()
        si = open('/dev/null', 'r')
        so = open('/dev/null', 'a+')
        se = open('/dev/null', 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # Write pid file
        if CONFIG.pid_file:
            pid = os.getpid()
            pidfile = open(CONFIG.pid_file, 'w')
            atexit.register(utils.rm_pidfile)
            pidfile.write("%s\n" % pid)
            pidfile.close()
    except OSError as error:
        utils.rm_pidfile(CONFIG)
        return "Cannot daemonize: %s" % error.strerror
    return None


def daemonize():
    """
    Creates a daemon from the current process.

    It uses helper file as a lock and then checks inside critical section
    whether pid file contains pid of a valid process.
    If not then it daemonizes itself, otherwise it dies.
    """
    if not _lock_pid():
        utils.die("Daemon already running. If you are sure it isn't please remove %s" %
                  _lock_pid_file_name())
    err = _try_daemonize()
    _unlock_pid()
    if err:
        utils.die("%s" % err)

    # Logging for daemon mode
    log_object.enable_daemon_mode()


def collect_log_names(system_info):
    """
    Collects standard local logs and identifies them.
    """
    logs = []
    for root, _, files in os.walk(LOG_ROOT):
        for name in files:
            if name[-3:] != '.gz' and re.match(r'.*\.\d+$', name) is None:
                logs.append(os.path.join(root, name))

    LOG.debug("Collected logs: %s", logs)
    try:

        conn = http.client.HTTPSConnection(LE_SERVER_API)
        request_ = {
            'logs': json.dumps(logs),
            'distname': system_info['distname'],
            'distver': system_info['distver']
        }
        LOG.debug("Requesting %s", request_)
        conn.request('post', ID_LOGS_API, urlencode(request_), {})
        response = conn.getresponse()
        if not response or response.status != 200:
            utils.die('Error: Unexpected response from logentries (%s).' %
                      response.status)
        data = json.loads(response.read())
        log_data = data['logs']

        LOG.debug("Identified logs: %s", log_data)

        return log_data

    except socket.error as msg:
        utils.die('Error: Cannot contact server, %s' % msg)
    except ValueError as msg:
        utils.die('Error: Invalid response from the server (Parsing error %s)' % msg)
    except KeyError:
        utils.die('Error: Invalid response from the server, log data not present.')


def release_test(filename, distname, system_info):
    """Check for release"""
    if os.path.isfile(filename):
        system_info['distname'] = distname
        system_info['distver'] = utils.rfile(filename)
        return True
    return False


def system_detect(details):
    """
    Detects the current operating system. Returned information contains:
        distname: distribution name
        distver: distribution version
        kernel: kernel type
        system: system name
        hostname: host name
    """
    uname = platform.uname()
    sys_ = uname[0]
    system_info = dict(system=sys, hostname=socket.getfqdn(),
                       kernel='', distname='', distver='')

    if not details:
        return system_info

    if sys_ == "SunOS":
        system_info['distname'] = call('cat /etc/product | sed -n "s/Name: \\(.*\\)/\\1/p"')
        system_info['distver'] = call('cat /etc/product | sed -n "s/Image: \\(.*\\)/\\1/p"')
        system_info['kernel'] = uname[2]
    elif sys_ == "AIX":
        system_info['distver'] = call("oslevel -r")
    elif sys_ == "Darwin":
        system_info['distname'] = call("sw_vers -productName")
        system_info['distver'] = call("sw_vers -productVersion")
        system_info['kernel'] = uname[2]

    elif sys_ == "Linux":
        system_info['kernel'] = uname[2]
        # XXX CentOS?
        releases = [
            ['/etc/debian_version', 'Debian'],
            ['/etc/UnitedLinux-release', 'United Linux'],
            ['/etc/annvix-release', 'Annvix'],
            ['/etc/arch-release', 'Arch Linux'],
            ['/etc/arklinux-release', 'Arklinux'],
            ['/etc/aurox-release', 'Aurox Linux'],
            ['/etc/blackcat-release', 'BlackCat'],
            ['/etc/cobalt-release', 'Cobalt'],
            ['/etc/conectiva-release', 'Conectiva'],
            ['/etc/fedora-release', 'Fedora Core'],
            ['/etc/gentoo-release', 'Gentoo Linux'],
            ['/etc/immunix-release', 'Immunix'],
            ['/etc/knoppix_version', 'Knoppix'],
            ['/etc/lfs-release', 'Linux-From-Scratch'],
            ['/etc/linuxppc-release', 'Linux-PPC'],
            ['/etc/mandriva-release', 'Mandriva Linux'],
            ['/etc/mandrake-release', 'Mandrake Linux'],
            ['/etc/mandakelinux-release', 'Mandrake Linux'],
            ['/etc/mklinux-release', 'MkLinux'],
            ['/etc/nld-release', 'Novell Linux Desktop'],
            ['/etc/pld-release', 'PLD Linux'],
            ['/etc/redhat-release', 'Red Hat'],
            ['/etc/slackware-version', 'Slackware'],
            ['/etc/e-smith-release', 'SME Server'],
            ['/etc/release', 'Solaris SPARC'],
            ['/etc/sun-release', 'Sun JDS'],
            ['/etc/SuSE-release', 'SuSE'],
            ['/etc/sles-release', 'SuSE Linux ES9'],
            ['/etc/tinysofa-release', 'Tiny Sofa'],
            ['/etc/turbolinux-release', 'TurboLinux'],
            ['/etc/ultrapenguin-release', 'UltraPenguin'],
            ['/etc/va-release', 'VA-Linux/RH-VALE'],
            ['/etc/yellowdog-release', 'Yellow Dog'],
        ]

        # Check for known system IDs
        for release in releases:
            if release_test(release[0], release[1], system_info):
                break
        # Check for general LSB system
        if os.path.isfile(LSB_RELEASE):
            try:
                fields = dict((a.split('=')
                               for a in utils.rfile(LSB_RELEASE).split('\n')
                               if len(a.split('=')) == 2))
                system_info['distname'] = fields['DISTRIB_ID']
                system_info['distver'] = fields['DISTRIB_RELEASE']
            except (ValueError, KeyError):
                pass
    return system_info


class Transport(object):

    """Encapsulates simple connection to a remote host. The connection may be
    encrypted. Each communication is started with the preamble."""

    def __init__(self, endpoint, port, use_ssl, preamble, debug_transport_events, proxy):
        # Copy transport configuration
        self.endpoint = endpoint
        self.port = port
        self.use_ssl = use_ssl
        self.preamble = preamble
        self._entries = Queue(SEND_QUEUE_SIZE)
        self._socket = None # Socket with optional TLS encyption
        self._debug_transport_events = debug_transport_events

        self._shutdown = False # Shutdown flag - terminates the networking thread

        # proxy setup
        self._use_proxy = False

        (proxy_type_str, self._proxy_url, self._proxy_port) = proxy

        if proxy_type_str != NOT_SET and self._proxy_url != NOT_SET and self._proxy_port != NOT_SET:
            self._use_proxy = True
            if proxy_type_str == "HTTP":
                self._proxy_type = socks.PROXY_TYPE_HTTP
            elif proxy_type_str == "SOCKS5":
                self._proxy_type = socks.PROXY_TYPE_SOCKS5
            elif proxy_type_str == "SOCKS4":
                self._proxy_type = socks.PROXY_TYPE_SOCKS4
            else:
                self._use_proxy = False
                LOG.error("Invalid proxy type. Only HTTP, SOCKS5 and SOCKS4 are accepted")

        if self._use_proxy:
            LOG.info("Using proxy with proxy_type: %s, proxy-url: %s, proxy-port: %s",
                     proxy_type_str, self._proxy_url, self._proxy_port)

        # Get certificate name
        if not CONFIG.use_ca_provided:
            cert_name = utils.system_cert_file()
            if cert_name is None:
                cert_name = utils.default_cert_file(CONFIG)
        else:
            cert_name = utils.default_cert_file(CONFIG)

        if use_ssl and not cert_name:
            utils.die('Cannot get default certificate file name to provide connection over SSL!')
            # XXX Do we need to die here?
        self._certs = cert_name

        # Start asynchronous worker
        self._worker = threading.Thread(target=self.run)
        self._worker.daemon = True
        self._worker.start()

    def _get_address(self, use_proxy):
        if use_proxy:
            return self.endpoint
        else:
            # Returns an IP address of the endpoint.
            # If the endpoint resolves to multiple addresses, a random one is selected.
            # This works better than default selection.
            return random.choice(
                socket.getaddrinfo(self.endpoint, self.port))[4][0]

    def _connect_ssl(self, plain_socket):
        """Connects the socket and wraps in SSL. Returns the wrapped socket
        or None in case of IO or other errors."""
        # FIXME this code ignores --local
        try:
            address = '-'
            address = self._get_address(self._use_proxy)
            socket_ = plain_socket
            socket_.connect((address, self.port))

            if FEAT_SSL:
                try:
                    socket_ = wrap_socket(
                        plain_socket, ca_certs=self._certs,
                        cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1,
                        ciphers="HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5")
                except TypeError:
                    socket_ = wrap_socket(
                        plain_socket, ca_certs=self._certs, cert_reqs=ssl.CERT_REQUIRED,
                        ssl_version=ssl.PROTOCOL_TLSv1)

                try:
                    match_hostname(socket_.getpeercert(), self.endpoint)
                except CertificateError as error:
                    utils.report("Could not validate SSL certificate for %s: %s"
                                 % (self.endpoint, error.message))
                    return None
            else:
                socket_ = wrap_socket(plain_socket, ca_certs=self._certs)
            return socket_

        except IOError as error:
            cause = error.strerror
            if not cause:
                cause = "(No reason given)"
            utils.report("Can't connect to %s/%s via SSL at port %s. "
                         "Make sure that the host and port are reachable and speak SSL: %s"
                         % (self.endpoint, address, self.port, cause))
        return None

    def _connect_plain(self, plain_socket):
        """Connects the socket with the socket given.
        Returns the socket or None in case of IO errors."""
        address = self._get_address(self._use_proxy)
        try:
            plain_socket.connect((address, self.port))
        except IOError as error:
            utils.report("Can't connect to %s/%s at port %s. "
                         "Make sure that the host and port are reachable\n"
                         "Error message: %s" % (self.endpoint, address, self.port, error.strerror))
            return None
        return plain_socket

    def _open_connection(self):
        """ Opens a push connection to logentries. """
        preamble = self.preamble.strip()
        if preamble:
            preamble = ' ' + preamble
        LOG.debug("Opening connection %s:%s%s",
                  self.endpoint, self.port, preamble)
        retry = 0
        delay = SRV_RECON_TO_MIN
        # Keep trying to open the connection
        while not self._shutdown:
            self._close_connection()
            try:
                if self._use_proxy:
                    socket_ = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_.setproxy(self._proxy_type, self._proxy_url, self._proxy_port)
                else:
                    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                socket_.settimeout(TCP_TIMEOUT)
                if self.use_ssl:
                    self._socket = self._connect_ssl(socket_)
                else:
                    self._socket = self._connect_plain(socket_)

                # If the socket is open, send preamble and leave
                if self._socket:
                    if self.preamble:
                        try:
                            self._socket.send(self.preamble)
                        except TypeError:
                            self._socket.send(str.encode(self.preamble))
                    break
            except socket.error:
                if self._shutdown:
                    return  # XXX

            # Wait between attempts
            time.sleep(delay)
            retry += 1
            delay *= 2
            if delay > SRV_RECON_TO_MAX:
                delay = SRV_RECON_TO_MAX

    def _close_connection(self):
        if self._socket:
            try:
                self._socket.close()
            except (AttributeError, socket.error):
                pass
            self._socket = None

    def _send_entry(self, entry):
        """Sends the entry. If the connection fails it will re-open it and try
        again."""
        # Keep sending data until successful
        while not self._shutdown:
            try:
                self._socket.send(entry.encode('utf8'))
                if self._debug_transport_events:
                    sys.stderr.write(entry.encode('utf8'))
                break
            except socket.error:
                self._open_connection()

    def send(self, entry):
        """Sends the entry given. Depending on transport configuration it will
        block until the entry is sent or it will queue the entry for async
        send.

        Note: entry must end with a new line
        """
        while True:
            try:
                self._entries.put_nowait(entry)
                break
            except queue.Full:
                try:
                    self._entries.get_nowait()
                except queue.Empty:
                    pass

    def close(self):
        """Close transport object"""
        self._shutdown = True
        self.send('') # Force the networking thread to check the shutdown flag
        self._worker.join(TRANSPORT_JOIN_INTERVAL)

    def run(self):
        """When run with background thread it collects entries from internal
        queue and sends them to destination."""
        self._open_connection()
        while not self._shutdown:
            try:
                try:
                    entry = self._entries.get(True, IAA_INTERVAL)
                except queue.Empty:
                    entry = IAA_TOKEN
                self._send_entry(entry + '\n')
            except Exception:
                LOG.error("Exception in run: %s", traceback.format_exc())
        self._close_connection()


class DefaultTransport(object):
    """Default Transport Class"""
    def __init__(self, xconfig):
        self._transport = None
        self._config = xconfig

    def get(self):
        """Get transport"""
        if not self._transport:
            use_ssl = not self._config.suppress_ssl
            if self._config.datahub:
                endpoint = self._config.datahub_ip
                port = self._config.datahub_port
            else:
                endpoint = Domain.DATA
                port = 443 if use_ssl else 80
            if CONFIG.force_domain:
                endpoint = self._config.force_domain
            elif self._config.force_data_host:
                endpoint = self._config.force_data_host
            if self._config.debug_local:
                endpoint = Domain.LOCAL
                port = 10000
                use_ssl = False
            self._transport = Transport(
                endpoint, port, use_ssl, '', self._config.debug_transport_events,
                (self._config.proxy_type, self._config.proxy_url, self._config.proxy_port))
        return self._transport

    def close(self):
        """Close transport object if open"""
        if self._transport:
            self._transport.close()


def _startup_info():
    """
    Prints correct startup information based on OS
    """
    if 'darwin' in sys.platform:
        LOG.info(
            '  sudo launchctl unload /Library/LaunchDaemons/com.logentries.agent.plist')
        LOG.info(
            '  sudo launchctl load /Library/LaunchDaemons/com.logentries.agent.plist')
    elif 'linux' in sys.platform:
        LOG.info('  sudo service logentries restart')
    elif 'sunos' in sys.platform:
        LOG.info('  sudo svcadm disable logentries')
        LOG.info('  sudo svcadm enable logentries')
    else:
        LOG.info('')


def do_request(conn, operation, addr, data=None, headers=None):
    """Perform request"""
    if not headers:
        headers = {}
        LOG.debug('Domain request: %s %s %s %s', operation, addr, data, headers)
    if data:
        conn.request(operation, addr, data, headers=headers)
    else:
        conn.request(operation, addr, headers=headers)


def get_response(operation, addr, data=None, headers=None,
                 silent=False, die_on_error=True, domain=Domain.API):
    """
    Returns response from the domain or API server.
    """
    if not headers:
        headers = {}
    try:
        conn = utils.domain_connect(CONFIG, domain, Domain)
        do_request(conn, operation, addr, data, headers)
        response = conn.getresponse()
        return response, conn
    except socket.sslerror as msg:  # Network error
        if not silent:
            LOG.info("SSL error: %s", msg)
    except socket.error as msg:  # Network error
        if not silent:
            LOG.debug("Network error: %s", msg)
    except http.client.BadStatusLine:
        error = "Internal error, bad status line"
        if die_on_error:
            utils.die(error)
        else:
            LOG.info(error)

    return None, None


def pull_request(what, params):
    """
    Processes a pull request on the logentries domain.
    """

    # Obtain response
    addr = '/%s/%s/?%s' % (
        CONFIG.user_key, quote(what), urlencode(params))
    response, conn = get_response("GET", addr, domain=Domain.PULL)

    # Check the response
    if not response:
        utils.die("Error: Cannot process LE request, no response")
    if response.status == 404:
        utils.die("Error: Log not found")
    if response.status != 200:
        utils.die("Error: Cannot process LE request: (%s)" % response.status)

    while True:
        data = response.read(65536)
        if len(data) == 0:
            break
        sys.stdout.write(data)
    conn.close()


def request(request_, required=False, check_status=False, rtype='GET', retry=False):
    """
    Processes a list request on the API server.
    """
    noticed = False
    while True:
        # Obtain response
        response, conn = get_response(
            rtype, quote('/' + CONFIG.user_key + '/' + request_),
            die_on_error=not retry)

        # Check the response
        if response:
            break
        if required:
            utils.die('Error: Cannot process LE request, no response')
        if retry:
            if not noticed:
                LOG.info('Error: No response from LE, re-trying in %ss intervals',
                         SRV_RECON_TIMEOUT)
                noticed = True
            time.sleep(SRV_RECON_TIMEOUT)
        else:
            return None

    response = response.read()
    conn.close()
    LOG.debug('List response: %s', response)
    try:
        d_response = json.loads(response.decode('UTF-8'))
    except (ValueError, TypeError):
        utils.error('Invalid response (%s)' % response)

    if check_status and d_response['response'] != 'ok':
        utils.error('%s' % d_response['reason'])

    return d_response


def generate_headers():
    """Generates headers for REST requests using the user_key"""
    CONFIG.api_key_required()
    return {
        'x-api-key': CONFIG.api_key,
        'Content-Type': 'application/json'
    }


def _try_get_request(url, headers):
    """Generic rest GET request"""
    try:
        return requests.request('GET', url, headers=headers)
    except (requests.RequestException, ValueError) as error:
        utils.die(error.message)


def _get_log(log_id=None):
    """
    Get the log with the given ID, if it exists.
    If no ID is provided, get all logs
    """
    url = LOG_URL + log_id if log_id else LOG_URL
    headers = generate_headers()
    try:
        response = _try_get_request(url, headers)
        if response.status_code is 200:
            return response.json()
        else:
            LOG.error("Could not retrieve log - %d", response.status_code)
            return None
    except requests.exceptions.RequestException as error:
        utils.die(error)


def _get_log_by_name(log_name):
    """Get a log by the name provided"""
    logs = _get_log()
    if logs is not None:
        for item in logs['logs']:
            if item['name'] is log_name:
                return item
    return False


def create_log(logset_id, name, filename, do_follow=True, source=None):
    """
    Creates a log on server with given parameters.
    """
    headers = generate_headers()

    params = {
        "log": {
            "name": name,
            "user_data": {
                "le_agent_filename": filename,
                "le_agent_follow": do_follow
            },
            "source_type": source,
            "logsets_info": [{
                "id": logset_id
            }]
        }
    }

    try:
        response = requests.post(LOG_URL, json=params, headers=headers)
        if response.status_code is 201:
            LOG.info("Created log with ID: %s", response.json()['log']['id'])
            return response.json()
        else:
            LOG.error("Error - %d. Could not create log.", response.status_code)
    except requests.exceptions.RequestException as error:
        utils.die(error)


def create_logset(name, filename="", follow=""):
    """
    Creates a new host on server with given parameters.
    """
    headers = generate_headers()
    platform_info = platform.dist()

    distribution = ""
    if platform_info[0]:
        distribution = platform_info[0]

    version = ""
    if platform_info[1]:
        version = platform_info[1]

    user_data = {
        'le_agent_filename': filename,
        'le_agent_follow': follow,
        'le_agent_distribution': distribution,
        'le_agent_distver': version
    }

    request_params = {
        'logset': {
            'name': name,
            'user_data': user_data
        }
    }

    try:
        response = requests.post(LOGSET_URL, json=request_params, headers=headers)
        if response.status_code is 201:
            return response.json()
        else:
            utils.die("Error - %d. Could not create logset. %s"
                      % (response.status_code, response.reason))
    except requests.exceptions.RequestException as error:
        utils.die(error)


def request_follow(filename, name):
    """
    Creates a new log to follow the file given.
    """
    CONFIG.agent_key_required()
    followed_log = create_log(CONFIG.agent_key, name, filename)
    print("Will follow %s as %s" % (filename, name))
    LOG.info("Don't forget to restart the daemon")
    _startup_info()
    return followed_log


def get_logset(logset_id=None):
    """
    Get the logset with the given ID, if it exists.
    If no ID is provided, get all logsets
    """
    url = LOGSET_URL + logset_id if logset_id else LOGSET_URL
    headers = generate_headers()

    try:
        response = _try_get_request(url, headers)
        if response.status_code is 200:
            return response.json()
        else:
            LOG.error("ERROR: %d - Could not retrieve logset %s for account ID %s.",
                      response.status_code, logset_id, CONFIG.user_key)
            return None
    except requests.exceptions.RequestException as error:
        utils.die(error)


def get_logset_by_name(logset_name):
    """Get a logset by the given name"""
    logsets = get_logset()
    if logsets is not None:
        for item in logsets['logsets']:
            if item['name'] is logset_name:
                return item
    return False


def get_or_create_logset(logset_name):
    """
    Gets or creates a new logset.
    """

    logset = get_logset_by_name(logset_name)

    if not logset:

        logset = create_logset(logset_name)

    return logset['logset']['id']


def get_or_create_log(logset_id, log_name):
    """
    Gets or creates a log for the logset given.
    It returns logs's token or None.
    """
    if not logset_id:
        return None

    logset = get_logset(logset_id)

    if logset is None:
        LOG.error("Logset: %s does not exist", logset_id)
        return None

    log_ = _get_log_by_name(log_name)

    if not log_:
        # Try to create the log
        new_log = create_log(logset_id, log_name, '', do_follow=False, source='token')
        new_log['log'].get('token', None)


    return log_['log'].get('token', None)


#
# Commands
#

def cmd_init(args):
    """
    Saves variables given to the configuration file. Variables not
    specified are not saved and thus are overwritten with default value.
    The configuration directory is created if it does not exit.
    """
    utils.no_more_args(args)
    CONFIG.user_key_required(True)
    CONFIG.save()
    LOG.info("Initialized")


def cmd_whoami(args):
    """
    Displays information about this host.
    """
    CONFIG.load()
    CONFIG.agent_key_required()
    utils.no_more_args(args)
    logset = get_logset(CONFIG.agent_key)
    logs = _get_loglist_with_paths()
    if logset is not None:
        LOG.info("name %s", utils.safe_get(logset, 'logset', 'name'))
        LOG.info("hostname %s", CONFIG.hostname)
        LOG.info("key %s", utils.safe_get(logset, 'logset', 'id'))
        LOG.info("distribution %s", utils.safe_get(logset, 'logset', 'user_data', 'le_distname'))
        LOG.info("distver %s", utils.safe_get(logset, 'logset', 'user_data', 'le_distver'))
        if logs is not None:
            LOG.info("logs:")
            for logname, filepath in logs.items():
                LOG.info("\tname %s", logname)
                LOG.info("\tpath %s", filepath)
        else:
            LOG.info("no logs")


def cmd_reinit(args):
    """
    Saves variables given to the configuration file. The configuration
    directory is created if it does not exit.
    """
    utils.no_more_args(args)
    CONFIG.load(load_include_dirs=False)
    CONFIG.save()
    LOG.info("Reinitialized")


def cmd_register(args):
    """
    Registers the agent in logentries infrastructure. The newly obtained
    agent key is stored in the configuration file.
    """
    utils.no_more_args(args)
    CONFIG.load()

    if CONFIG.agent_key != NOT_SET and not CONFIG.force:
        utils.report("Warning: Server already registered. "
                     "Use --force to override current registration.\n")
        return
    CONFIG.user_key_required(True)
    CONFIG.hostname_required()
    CONFIG.name_required()

    system_info = system_detect(True)

    logset = create_logset(CONFIG.name)
    CONFIG.agent_key = logset['logset']['id']
    CONFIG.save()

    LOG.info("Registered %s (%s)", CONFIG.name, CONFIG.hostname)

    # Registering logs
    logs = []
    if CONFIG.std or CONFIG.std_all:
        logs = collect_log_names(system_info)
    for log_ in logs:
        if CONFIG.std_all or log_['default'] == '1':
            request_follow(log_['filename'], log_['name'])


def check_file_name(file_name):
    """
    The function checks for 2 things: 1) that the path is not empty;
    2) the path starts with '/' character which indicates that the log has
    a "physical" path which starts from filesystem root.
    """
    return file_name.startswith('/')


def get_filters(available_filters, filter_filenames, log_name, log_id, log_filename, log_token):
    """Get filters by log name, ID or token"""
    if not filter_filenames(log_filename):
        _debug_filters(
            " Log blocked by filter_filenames, not following")
        LOG.info(
            'Not following %s, blocked by filter_filenames', log_name)
        return None
    _debug_filters(
        " Looking for filters by log_name=%s log_id=%s token=%s", log_name, log_id, log_token)

    entry_filter = None
    if not entry_filter and log_name:
        _debug_filters(" Looking for filters by log name")
        entry_filter = available_filters.get(log_name)
        if not entry_filter:
            _debug_filters(" No filter found by log name")

    if not entry_filter and log_id:
        _debug_filters(" Looking for filters by log ID")
        entry_filter = available_filters.get(log_id)
        if not entry_filter:
            _debug_filters(" No filter found by log ID")

    if not entry_filter and log_token:
        _debug_filters(" Looking for filters by token")
        entry_filter = available_filters.get(log_token)
        if not entry_filter:
            _debug_filters(" No filter found by token")

    if entry_filter and not hasattr(entry_filter, '__call__'):
        _debug_filters(
            " Filter found, but ignored because it's not a function")
        entry_filter = None
    if not entry_filter:
        entry_filter = filter_events
        _debug_filters(" No filter found")
    else:
        _debug_filters(" Using filter %s", entry_filter)
    return entry_filter


def get_formatters(available_formatters,
                   log_name, log_id, log_token):
    """Get formatters by log name, ID or token"""
    default_formatter = formats.get_formatter(CONFIG.formatter,
                                              CONFIG.hostname, log_name, log_token)
    _debug_formatters(
        " Looking for formatters by log_name=%s id=%s token=%s", log_name, log_id, log_token)

    entry_formatter = None
    if not entry_formatter and log_name:
        _debug_formatters(" Looking for formatters by log name")
        entry_formatter = available_formatters.get(log_name)
        if not entry_formatter:
            _debug_formatters(" No formatter found by log name")

    if not entry_formatter and log_id:
        _debug_formatters(" Looking for formatters by log ID")
        entry_formatter = available_formatters.get(log_id)
        if not entry_formatter:
            _debug_formatters(" No formatter found by log ID")

    if not entry_formatter and log_token:
        _debug_formatters(" Looking for formatters by token")
        entry_formatter = available_formatters.get(log_token)
        if not entry_formatter:
            _debug_formatters(" No formatter found by token")

    if entry_formatter and not hasattr(entry_formatter, '__call__'):
        _debug_formatters(
            " Formatter found, but ignored because it's not a function")
        entry_formatter = None

    if entry_formatter:
        form = entry_formatter(CONFIG.hostname, log_name, log_token)
        _debug_formatters(" Formatter found")
    else:
        form = default_formatter
        _debug_formatters(" No formatter found")

    return form


def config_filters():
    """Configure available filters"""
    available_filters = {}
    filter_filenames = default_filter_filenames
    if CONFIG.filters != NOT_SET:
        sys.path.append(CONFIG.filters)
        try:
            import filters

            available_filters = getattr(filters, 'filters', {})
            filter_filenames = getattr(
                filters, 'filter_filenames', default_filter_filenames)

            _debug_filters("Available filters: %s", available_filters.keys())
            _debug_filters("Filter filenames: %s", filter_filenames)
        except Exception:
            LOG.error('Cannot import event filter module %s: %s',
                      CONFIG.filters, sys.exc_info()[1])
            LOG.error('Details: %s', traceback.print_exc(sys.exc_info()))

    return (available_filters, filter_filenames)


def config_formatters():
    """Configure available formatters"""
    available_formatters = {}
    if CONFIG.formatters != NOT_SET:
        sys.path.append(CONFIG.formatters)
        try:
            import formatters #pylint: disable=import-error

            available_formatters = getattr(formatters, 'formatters', {})
            _debug_formatters("Available formatters: %s", available_formatters.keys())
        except Exception:
            LOG.error('Cannot import event formatter module %s: %s',
                      CONFIG.formatters, sys.exc_info()[1])
            LOG.error('Details: %s', traceback.print_exc(sys.exc_info()))
    return available_formatters


def extract_token(log_):
    """Extract the log token value if it exists"""
    return utils.safe_get(log_, 'log', 'token_seed')


def construct_configured_log(configured_log):
    """Create a configured log object"""
    return {
        'log': {
            'name': configured_log.name,
            'id': configured_log.log_id,
            'source_type': 'token',
            'tokens': [configured_log.token],
            'user_data': {
                'le_agent_filename': configured_log.path,
                'le_agent_follow': 'true'
            },
            'formatter': configured_log.formatter
        }
    }


def _get_all_logs_for_host():
    """Gets logs and configured logs for the host"""
    logs = []
    if CONFIG.pull_server_side_config:
        CONFIG.agent_key_required()
        logsets = get_logset(CONFIG.agent_key)
        log_ids = []

        for log_info in logsets['logset']['logs_info']:
            log_ids.append(log_info['id'])

        for log_id in log_ids:
            log_ = _get_log(log_id)
            if log_ is not None and 'user_data' in log_['log']:
                user_data = log_['log']['user_data']
                if 'le_agent_follow' in user_data and user_data['le_agent_follow'] == "true":
                    logs.append(log_)

    for configured_log in CONFIG.configured_logs:
        logs.append(construct_configured_log(configured_log))

    return logs


def start_followers(default_transport, states):
    """ Loads logs from the server (or configuration) and initializes followers.
    """
    logs = _get_all_logs_for_host()
    followers = []
    multilog_followers = []
    transports = []

    filter_config = config_filters()
    available_formatters = config_formatters()

    for log_ in logs:
        transport = default_transport.get()

        multilog_filename = False
        log_filename = log_['log']['user_data']['le_agent_filename']
        log_name = log_['log']['name']
        log_id = log_['log']['id']
        log_token = extract_token(log_)
        if log_token is None:
            log_token = ""

        if log_filename.startswith(PREFIX_MULTILOG_FILENAME):
            log_filename = log_filename.replace(PREFIX_MULTILOG_FILENAME, '', 1).lstrip()
            if not CONFIG.validate_pathname(None, False, log_filename):
                continue
            multilog_filename = True

        # Do not start a follower for a log with absent filepath.
        if not check_file_name(log_filename):
            continue

        entry_filter = get_filters(filter_config[0], filter_config[1],
                                   log_name, log_id, log_filename,
                                   log_token)
        if not entry_filter:
            continue

        entry_formatter = get_formatters(available_formatters,
                                         log_name, log_id, log_token)

        LOG.info("Following %s", log_filename)

        if log_token is not None or CONFIG.datahub is not None:
            transport = default_transport.get()
        elif log_id is not None:
            endpoint = Domain.DATA

            use_ssl = not CONFIG.suppress_ssl
            port = 443 if use_ssl else 80

            if CONFIG.force_domain:
                endpoint = CONFIG.force_domain
            if CONFIG.debug_local:
                endpoint = Domain.LOCAL
                port = 8081
                use_ssl = False
            preamble = 'PUT /%s/hosts/%s/%s/?realtime=1 HTTP/1.0\r\n\r\n' % (
                CONFIG.user_key, CONFIG.agent_key, log_id)

            # Special case for HTTP PUT
            # Use plain formatter if no formatter is defined
            transport = Transport(endpoint, port, use_ssl, preamble,
                                  CONFIG.debug_transport_events,
                                  (CONFIG.proxy_type, CONFIG.proxy_url, CONFIG.proxy_port))
            transports.append(transport)
            # Default formatter is plain
            if not entry_formatter:
                entry_formatter = formats.get_formatter('plain',
                                                        CONFIG.hostname, log_name, log_token)

        # Default formatter is syslog
        if not entry_formatter:
            entry_formatter = formats.get_formatter('syslog',
                                                    CONFIG.hostname, log_name, log_token)

        # Instantiate the follow_multilog for 'multilog' filename,
        # otherwise the individual follower
        if multilog_filename:
            follow_multilog = MultilogFollower(log_filename, entry_filter, entry_formatter,
                                               transport, states, CONFIG)
            multilog_followers.append(follow_multilog)
        else:
            follower = Follower(log_filename, entry_filter, entry_formatter,
                                transport, states.get(log_filename), CONFIG)
            followers.append(follower)

    return (followers, transports, multilog_followers)


def _is_followed(filename):
    """Checks if the file given is followed.
    """
    logs = _get_log()
    host_logs = []

    if logs is None:
        return False
    keyname = 'log' if 'log' in logs else 'logs'
    if keyname in logs:
        for ilog in logs[keyname]:
            if 'logsets_info' in ilog:
                for logset_info in ilog['logsets_info']:
                    if logset_info['id'] == CONFIG.agent_key:
                        host_logs.append(ilog)


    if host_logs is not None:
        for ilog in host_logs:
            if 'user_data' in ilog:
                user_data = ilog['user_data']
                if ('le_agent_follow' in user_data and
                        (user_data['le_agent_follow'] == "true" and
                         user_data['le_agent_filename'] == filename)):
                    return True
    return False


def _get_filename_if_followed(log_):
    if 'user_data' in log_:
        user_data = log_['user_data']
        if 'le_agent_follow' in user_data and user_data['le_agent_follow'] == "true":
            return str(user_data['le_agent_filename'])
    return None


def _get_loglist_with_paths():
    """Returns a list of all destination logs on the logentries infrastructure for
    a host with the path that the log is using for following a file or multiple files
    """

    logs = _get_log()
    result = {}
    CONFIG.agent_key_required()

    if logs is None:
        return False
    keyname = 'log' if 'log' in logs else 'logs'
    if keyname in logs:
        for ilog in logs[keyname]:
            if 'logsets_info' in ilog:
                for logset_info in ilog['logsets_info']:
                    if logset_info['id'] == CONFIG.agent_key:
                        filename = _get_filename_if_followed(ilog)
                        if filename is not None:
                            result[str(ilog['name'])] = filename
    return result


def create_configured_logs(configured_logs):
    """ Get tokens for all configured logs. Logs with no token specified are
    retrieved via API and created if needed.
    """
    for clog in configured_logs:
        if not clog.destination and not clog.token:
            LOG.debug("Not following logs for application `%s' "
                      "as neither `%s' nor `%s' parameter is specified",
                      clog.name, TOKEN_PARAM, DESTINATION_PARAM)
            continue

        if clog.destination and not clog.token:
            try:
                (logset_name, logname) = clog.destination.split('/', 1)
                logset_id = get_or_create_logset(logset_name)
                token = get_or_create_log(logset_id, logname)
                if not token:
                    LOG.error('Ignoring section %s, cannot create log', clog.name)

                clog.token = token
            except ValueError:
                LOG.error('Ignoring section %s since `%s\' does not contain host',
                          clog.name, DESTINATION_PARAM)


def _load_state(state_file):
    """Tries to load the state from the file provided"""
    if state_file:
        try:
            stat_file = open(state_file, 'r')
            state_s = stat_file.read()
            stat_file.close()

            state = json.loads(state_s)
            return state
        except (IOError, ValueError, KeyError):
            pass
    return {} # Fallback


def save_state(state_file, followers):
    """Collect state from all followers and save"""
    if state_file:
        states = {}
        for follower in followers:
            states[follower.get_name()] = follower.get_state()
        try:
            tmp_name = CONFIG.state_file + '.tmp'
            sfile = open(tmp_name, 'w')
            content = json.dumps(states, sort_keys=True, indent=2) + '\n'
            sfile.write(content)
            sfile.close()

            os.rename(tmp_name, CONFIG.state_file)
        except IOError:
            pass


class TerminationNotifier(object):
    """Termination Notifier Class"""
    terminate = False

    # pylint: disable=unused-argument
    def __init__(self):
        signal.signal(signal.SIGINT, self.signal_callback)
        signal.signal(signal.SIGTERM, self.signal_callback)

    def signal_callback(self, signum, frame):
        """Sets terminate to true"""
        self.terminate = True


def cmd_monitor(args):
    """Monitors host activity and sends events collected to logentries
    infrastructure.
    """
    utils.no_more_args(args)
    CONFIG.load()

    # We need account and host ID to get server side configuration
    if CONFIG.pull_server_side_config:
        CONFIG.user_key_required(not CONFIG.daemon)
        CONFIG.agent_key_required()

    # Ensure all configured logs are created
    if CONFIG.configured_logs and not CONFIG.datahub:
        create_configured_logs(CONFIG.configured_logs)

    if CONFIG.daemon:
        daemonize()

    # Start default transport channel
    default_transport = DefaultTransport(CONFIG)

    formatter = formats.FormatSyslog(CONFIG.hostname, 'le', CONFIG.metrics.token)
    smetrics = metrics.Metrics(CONFIG.metrics, default_transport,
                               formatter, CONFIG.debug_metrics)
    smetrics.start()

    followers = []
    transports = []
    follow_multilogs = []
    terminate = TerminationNotifier()
    try:
        state = _load_state(CONFIG.state_file)

        # Load logs to follow and start following them
        if not CONFIG.debug_stats_only:
            (followers, transports, follow_multilogs) = \
                start_followers(default_transport, state)

        # Periodically save state
        while not terminate.terminate:
            save_state(CONFIG.state_file, followers)

            time.sleep(1)
    except KeyboardInterrupt:
        pass

    sys.stderr.write("\nShutting down")
    sys.stderr.write("\n")
    # Stop metrics
    if smetrics:
        smetrics.cancel()
    # Close followers
    for follower in followers:
        follower.close()
    # Close each follow_multilog and the followers it holds
    for follow_multilog in follow_multilogs:
        follow_multilog.close()
    # Close transports
    for transport in transports:
        transport.close()
    default_transport.close()
    # Collect statuses
    save_state(CONFIG.state_file, followers)


def cmd_monitor_daemon(args):
    """Monitors as a daemon host activity and sends events collected to
    logentries infrastructure.
    """
    CONFIG.daemon = True
    cmd_monitor(args)


def cmd_follow(args):
    """
    Follow the log file given.
    """
    if len(args) == 0:
        utils.error("Specify the file name of the log to follow.")
    if len(args) > 1:
        utils.error("Too many arguments.\n"
                    "A common mistake is to use wildcards in path that is being "
                    "expanded by shell. Enclose the path in single quotes to avoid "
                    "expansion.")

    CONFIG.load()
    CONFIG.agent_key_required()
    # FIXME: follow to add logs into local configuration

    arg = args[0]
    filename = os.path.abspath(arg)
    name = CONFIG.name
    if name == NOT_SET:
        name = os.path.basename(filename)

    # Check that we don't follow that file already
    if not CONFIG.force and _is_followed(filename):
        LOG.warning('Already following %s', filename)
        return

    if len(glob.glob(filename)) == 0:
        LOG.warning('\nWarning: File %s does not exist\n', filename)

    request_follow(filename, name)


def cmd_follow_multilog(args):
    """
    Follow the log(s) as defined in string passed to agent with
    the '--multilog' parameter included - modification of cmd_follow
    """
    if len(args) == 0:
        utils.error("Specify the file name of the log to follow.")
    if len(args) > 1:
        utils.error("Too many arguments.\n"
                    "A common mistake is to use wildcards in path that is being "
                    "expanded by shell. Enclose the path in single quotes to avoid "
                    "expansion.")
    CONFIG.load()
    CONFIG.agent_key_required()
    arg = args[0]
    path = os.path.abspath(arg)
    # When testing ignore user input
    if CONFIG.debug_multilog:
        follow = True
    else:
        follow = _user_prompt(path)
    if follow:
        name = CONFIG.name
        if name == NOT_SET:
            name = os.path.basename(path)

        filename = PREFIX_MULTILOG_FILENAME + path
        request_follow(filename, name)


def _user_prompt(path):
    """
    Displays 2 lists - files already followed with log names, and those not.
    Prompts user if they wish to follow files or not
    """
    file_candidates = glob.glob(path)
    loglist_with_paths = _get_loglist_with_paths()

    print("\nExisting destination Logs for this host and the associated Paths are:")
    print('\t{0:50}{1}'.format('LOGNAME', 'PATH'))
    for logname, filepath in loglist_with_paths.items():
        # Test if an identical path is already in use!
        if path == filepath.replace(PREFIX_MULTILOG_FILENAME, '', 1).lstrip():
            print('\t{0:40}{1:10}{2}'.format(logname, "IDENTICAL", filepath))
            print("NOTE: there are destination logs in above list with identical paths.")
        else:
            print('\t{0:50}{1}'.format(logname, filepath))
    print("\nRequested path is: %s" % path)
    if len(file_candidates) == 0:
        print("\nNo Files were found for this path at this time.\n")
    else:
        print("\nFiles found for this path:")
        file_count = 0
        for filename in file_candidates:
            if file_count < MAX_FILES_FOLLOWED:
                print('\t{0}'.format(filename))
                file_count = file_count+1
    while True:
        print("\nUse new path to follow files [y] or quit [n]?")
        user_resp = input().lower()
        if user_resp == 'n':
            sys.exit(EXIT_OK)
        elif user_resp == 'y':
            return True
        else:
            print("Please try again")


def cmd_followed(args):
    """
    Check if the log file given is followed.
    """
    if len(args) == 0:
        utils.error("Specify the file name of the log to test.")
    if len(args) != 1:
        utils.error("Too many arguments. Only one file name allowed.")
    CONFIG.load()
    CONFIG.agent_key_required()

    filename = os.path.abspath(args[0])

    # Check that we don't follow that file already
    if _is_followed(filename):
        print('Following %s' % filename)
        sys.exit(EXIT_OK)
    else:
        print('NOT following %s' % filename)
        sys.exit(EXIT_NO)


def cmd_clean(args):
    """
    Wipes out old configuration file.
    """
    utils.no_more_args(args)
    if CONFIG.clean():
        LOG.info('Configuration clean')


def _logtype_name(logtype_uuid):
    """ Provides name for the logtype given.
    """
    # Look for embedded structures
    for structure_name, structure_id in EMBEDDED_STRUCTURES.items():
        if structure_id == logtype_uuid:
            return structure_name

    # Search for logtypes provided by the backend
    response = request('logtypes', True, True)
    all_logtypes = response['list']
    for logtype in all_logtypes:
        if logtype_uuid == logtype['key']:
            return logtype['shortcut']

    return 'unknown'


def _list_object(request_, hostnames=False):
    """
    Lists object request given.
    """
    if utils.safe_get(request_, 'log') is not None:
        print(json.dumps(request_['log']))
    elif utils.safe_get(request_, 'logs') is not None:
        print(json.dumps(request_['logs']))
    elif utils.safe_get(request_, 'logset') is not None:
        print(json.dumps(request_['logset']))

    obj = request_['object']
    index_name = 'name'
    item_name = ''
    if obj == 'rootlist':
        item_name = 'item'
    elif obj == 'host':
        print('name =', request_['name'])
        print('hostname =', request_['hostname'])
        print('key =', request_['key'])
        print('distribution =', request_['distname'])
        print('distver =', request_['distver'])
        return
    elif obj == 'list':
        print('name =', request_['name'])
        return
    elif obj == 'hostlist':
        item_name = 'host'
        if hostnames:
            index_name = 'hostname'
    elif obj == 'logtype':
        print('title =', request_['title'])
        print('description =', request_['desc'])
        print('shortcut =', request_['shortcut'])
        return
    elif obj == 'loglist':
        item_name = 'log'
    elif obj == 'logtypelist':
        item_name = 'logtype'
        index_name = 'shortcut'
    else:
        utils.die('Unknown object type "%s". Agent too old?' % object)

    # Standard list, print it sorted
    ilist = request_['list']
    ilist = sorted(ilist, key=lambda item: item[index_name])
    for item in ilist:
        if CONFIG.uuid:
            print(item['key'])
        print("%s" % (item[index_name]))

    utils.print_total(ilist, item_name)


def _is_log_fs(addr):
    """Tests if the address points for a log.
    """
    log_addrs = [r'(logs|apps)/.*/',
                 r'host(name)?s/.*/.*/']
    for log_addr in log_addrs:
        if re.match(log_addr, addr):
            return True
    return False


def cmd_ls_ips():
    """
    List IPs used by the agent.
    """
    ips = []
    for name in [Domain.MAIN, Domain.API, Domain.DATA, Domain.PULL]:
        for info in socket.getaddrinfo(name, None, 0, 0, socket.IPPROTO_TCP):
            ip_addr = info[4][0]
            sys.stderr.write('%-16s %s' % (ip_addr, name))
            ips.append(ip_addr)
    print(ips)
    print(' '.join(ips))


def cmd_ls(args):
    """
    General list command
    """
    if len(args) == 1 and args[0] == 'ips':
        cmd_ls_ips()
        return
    if len(args) == 0:
        args = ['/']
    CONFIG.load()
    CONFIG.user_key_required(True)

    addr = args[0]
    if addr.startswith('/'):
        addr = addr[1:]
    # Make sure we are not downloading log
    if _is_log_fs(addr):
        utils.die('Use pull to get log content.')

    _list_object(request(addr, True, True),
                 hostnames=addr.startswith('hostnames'))


def cmd_rm(args):
    """
    General remove command
    """
    if len(args) == 0:
        args = ['/']
    CONFIG.load()
    CONFIG.user_key_required(True)

    addr = args[0]

    headers = generate_headers()
    try:
        response = requests.delete(addr, headers=headers)
        if response.status_code is 204:
            LOG.info("Successfully deleted \n")
        else:
            LOG.error('Deleting resource failed, status code: %d %s',
                      response.status_code, response.reason)
    except requests.exceptions.RequestException as error:
        utils.die(error)


def cmd_pull(args):
    """
    Log pull command
    """
    if len(args) == 0:
        utils.die(PULL_USAGE)
    CONFIG.load()
    CONFIG.user_key_required(True)

    params = {}

    addr = args[0]
    if addr.startswith('/'):
        addr = addr[1:]
    if addr.endswith('/'):
        addr = addr[:-1]
    if not _is_log_fs(addr + '/'):
        utils.die('Error: Not a log')

    if len(args) > 1:
        time_range = parse_timestamp_range(args[1])
        params['start'] = time_range[0]
        params['end'] = time_range[1]
    if len(args) > 2:
        params['filter'] = args[2]
    if len(args) > 3:
        try:
            limit = int(args[3])
            if limit < 1:
                utils.die('Limit must be above 0')
            params['limit'] = limit
        except ValueError:
            utils.die('Error: Limit must be integer')

    pull_request(addr, params)
    requests.get(addr,)


#
# Main method
#
def main_root():
    """Serious business starts here.
    """
    # Read command line parameters
    args = CONFIG.process_params(sys.argv[1:])

    if CONFIG.debug:
        LOG.setLevel(logging.DEBUG)
    if CONFIG.debug_system:
        utils.die(system_detect(True))
    if CONFIG.debug_loglist:
        utils.die(collect_log_names(system_detect(True)))

    if CONFIG.debug_cmd_line:
        sys.stderr.write('Debug command line args: %s' % args)

    argv0 = sys.argv[0]
    if argv0 and argv0 != '':
        pname = os.path.basename(argv0).split('-')
        if len(pname) != 1:
            args.insert(0, pname[-1])

    if len(args) == 0:
        utils.report(USAGE)
        sys.exit(EXIT_HELP)

    commands = {
        'init': cmd_init,
        'reinit': cmd_reinit,
        'register': cmd_register,
        'monitor': cmd_monitor,
        'monitordaemon': cmd_monitor_daemon,
        'follow': cmd_follow,
        'followed': cmd_followed,
        'clean': cmd_clean,
        'whoami': cmd_whoami,
        # Filesystem operations
        'ls': cmd_ls,
        'rm': cmd_rm,
        'pull': cmd_pull,
    }
    for cmd, func in commands.items():
        if cmd == args[0]:
            if CONFIG.multilog and cmd == 'follow':
                return cmd_follow_multilog(args[1:])
            else:
                return func(args[1:])
    utils.die('Error: Unknown command "%s".' % args[0])


def main():
    """Main method"""
    try:
        main_root()
    except FatalConfigurationError as error:
        LOG.error("Fatal: %s", error)
    except KeyboardInterrupt:
        utils.die("\nTerminated", EXIT_TERMINATED)


if __name__ == '__main__':
    main()
