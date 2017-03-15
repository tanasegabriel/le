"""Utils Module"""
#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:

#pylint: disable=invalid-name
#pylint: disable=wrong-import-order, wrong-import-position
from __future__ import absolute_import

from future.standard_library import install_aliases

install_aliases()
from urllib.parse import urlencode #pylint: disable=import-error

import errno
import os
import re
import socket
import sys
import logging
import json
import getpass
import http.client

from .domain import Domain
from .__init__ import __version__
from .constants import * #pylint: disable=unused-wildcard-import,wildcard-import
from .backports import match_hostname, CertificateError

try:
    import uuid
    FEAT_UUID = True
except ImportError:
    FEAT_UUID = False


try:
    import termcolor
    colored = termcolor.colored
except ImportError:
    def colored(text, color):
        return text

def red(text):
    return colored('%s'%text, 'red')

def c_param(text):
    return colored('%s'%text, 'green')

def c_id(text):
    return colored('%s'%text, 'cyan')


__author__ = 'Logentries'

__all__ = ["EXIT_OK", "EXIT_NO", "EXIT_HELP", "EXIT_ERR", "EXIT_TERMINATED",
           "ServerHTTPSConnection", "LOG_LE_AGENT", "create_conf_dir",
           "default_cert_file", "system_cert_file", "domain_connect",
           "no_more_args", "find_hosts", "find_logs", "find_api_obj_by_key", "find_api_obj_by_name", "die",
           "error", "cmp_patterns",
           "rfile", 'TCP_TIMEOUT', "rm_pidfile", "uuid_parse", "report",
           "colored", "c_param", "c_id"]


AUTHORITY_CERTIFICATE_FILES = [
    # Debian 5.x, 6.x, 7.x, Ubuntu 9.10, 10.4, 13.0
    "/etc/ssl/certs/ca-certificates.crt",
    # Fedora 12, Fedora 13, CentOS 5
    "/usr/share/purple/ca-certs/GeoTrust_Global_CA.pem",
    # Amazon AMI, CentOS 7, recent RHs
    "/etc/pki/tls/certs/ca-bundle.crt",
    # FreeBSD 10.2
    "/etc/ssl/cert.pem"]



log = logging.getLogger(LOG_LE_AGENT)

try:
    import ssl

    wrap_socket = ssl.wrap_socket
    FEAT_SSL = True
    try:
        ssl.create_default_context()
        FEAT_SSL_CONTEXT = True
    except AttributeError:
        FEAT_SSL_CONTEXT = False
except ImportError:
    FEAT_SSL = False
    FEAT_SSL_CONTEXT = False

    def wrap_socket(sock):
        """Wrap socket"""
        return socket.ssl(sock)

def report(what):
    """Write text to stderr"""
    sys.stderr.write(what)
    sys.stderr.write("\n")

class ServerHTTPSConnection(http.client.HTTPSConnection):
    """
    A slight modification of HTTPSConnection to verify the certificate
    """
    def __init__(self, config, server, port, cert_file): #pylint: disable=super-init-not-called
        self.no_ssl = config.suppress_ssl or not FEAT_SSL
        if self.no_ssl:
            self.config_connection(config, server, port, None, None)
        else:
            self.cert_file = cert_file
            if FEAT_SSL_CONTEXT:
                context = ssl.create_default_context(cafile=cert_file)
                self.config_connection(config, server, port, context, None)
            else:
                self.config_connection(config, server, port, None, cert_file)


    def config_connection(self, config, server, port, context, cert_file):
        """Create https connection with config provided"""
        if config.use_proxy:
            http.client.HTTPSConnection.__init__(self,
                                                 config.proxy_url,
                                                 config.proxy_port,
                                                 context=context)
            http.client.HTTPSConnection.set_tunnel(self, server, port)
        else:
            http.client.HTTPSConnection.__init__(self, server, port, cert_file=cert_file)


    def connect(self):
        """Create http(s) connection"""
        if FEAT_SSL_CONTEXT:
            http.client.HTTPSConnection.connect(self)
        else:
            if self.no_ssl:
                return http.client.HTTPSConnection.connect(self)
            sock = create_connection(self.host, self.port)
            try:
                if self._tunnel_host:
                    self.sock = sock
                    self._tunnel()
            except AttributeError:
                pass
            self.sock = wrap_socket(sock)
            try:
                match_hostname(self.sock.getpeercert(), self.host)
            except CertificateError as error:
                die("Could not validate SSL certificate for %s: %s"
                    % (self.host, error.message))


def default_cert_file_name(config):
    """
    Construct full file name to the default certificate file.
    """
    return config.config_dir_name + LE_CERT_NAME


def create_conf_dir(config):
    """
    Creates directory for the configuration file.
    """
    # Create logentries config
    try:
        os.makedirs(config.config_dir_name)
    except OSError as error:
        if error.errno != errno.EEXIST:
            if error.errno == errno.EACCES:
                die("You don't have permission to create logentries config file. "
                    "Please run logentries agent as root.")
            die('Error: %s' % error)


def write_default_cert_file(config):
    """
    Writes default certificate file in the configuration directory.
    """
    create_conf_dir(config)
    cert_filename = default_cert_file_name(config)
    cert_file = open(cert_filename, 'wb')
    cert_file.write(get_bundled_certs())
    cert_file.close()


def default_cert_file(config):
    """
    Returns location of the default certificate file or None. It tries to write the
    certificate file if it is not there or it is outdated.
    """
    cert_filename = default_cert_file_name(config)
    try:
        # If the certificate file is not there, create it
        if not os.path.exists(cert_filename):
            write_default_cert_file(config,)
            return cert_filename

        # If it is there, check if it is outdated
        curr_cert = rfile(cert_filename)
        if curr_cert != AUTHORITY_CERTIFICATE:
            write_default_cert_file(config)
    except IOError:
        # Cannot read/write certificate file, ignore
        return None
    return cert_filename


def system_cert_file():
    """
    Finds the location of our lovely site's certificate on the system or None.
    """
    for cert_file in AUTHORITY_CERTIFICATE_FILES:
        if os.path.exists(cert_file):
            return cert_file
    return None


def create_connection(host, port):
    """
    A simplified version of socket.create_connection from Python 2.6.
    """
    for addr_info in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, stype, proto, server_addr = addr_info
        soc = None
        try:
            soc = socket.socket(af, stype, proto)
            soc.settimeout(TCP_TIMEOUT)
            soc.connect(server_addr)
            return soc
        except socket.error:
            soc.close()

    raise socket.error("Cannot make connection to %s:%s" % (host, port))


def make_https_connection(config, server, port):
    """
    Makes HTTPS connection. Tried all available certificates.
    """
    if not config.use_ca_provided:
        # Try to connect with system certificate
        try:
            cert_file = system_cert_file()
            if cert_file:
                return ServerHTTPSConnection(config, server, port, cert_file)
        except socket.error:
            pass

    # Try to connect with our default certificate
    cert_file = default_cert_file(config)
    if not cert_file:
        die('Error: Cannot find suitable CA certificate.')
    return ServerHTTPSConnection(config, server, port, cert_file)


def get_server_address(config, domain, _domain):
    """Find the correct server address"""
    server = domain

    if _domain == Domain.API:
        if config.force_domain:
            server = config.force_domain
        elif config.force_api_host:
            server = config.force_api_host
        else:
            server = Domain.API

    if config.debug_local:
        if server == Domain.API:
            server = Domain.API_LOCAL
        else:
            server = Domain.MAIN_LOCAL

    return server


def get_port(config, use_ssl, server):
    """Return port based on config provided"""
    port = 443 if use_ssl else 80

    if config.debug_local:
        port = 8000 if server == Domain.API else 8081

    return port


def get_ssl(config, server):
    """Determine whether or not to use SSL
        Never use SSL for debugging, always with main server"""
    use_ssl = True
    if config.debug_local:
        use_ssl = False
    elif server == Domain.API:
        use_ssl = not config.suppress_ssl

    return use_ssl


def domain_connect(config, domain, _domain):
    """
    Connects to the domain specified.
    """
    server = get_server_address(config, domain, _domain)
    use_ssl = get_ssl(config, server)
    port = get_port(config, use_ssl, server)

    log.debug('Connecting to %s:%s', server, port)

    # Pass the connection
    if use_ssl:
        return make_https_connection(config, server, port)
    else:
        if config.use_proxy:
            conn = http.client.HTTPConnection(config.proxy_url, config.proxy_port)
            conn.set_tunnel(server, port)
            return conn
        else:
            return http.client.HTTPConnection(server, port)


def no_more_args(args):
    """
    Exits if there are any arguments given.
    """
    if len(args) != 0:
        die("No more than one argument is expected.")


def expr_match(expr, text):
    """
    Returns True if the text matches with expression. If the expression
    starts with / it is a regular expression.
    """
    if expr[0] == '/':
        if re.match(expr[1:], text):
            return True
    else:
        if expr[0:2] == '\\/':
            return text == expr[1:]
        else:
            return text == expr
    return False


def find_hosts(expr, hosts):
    """
    Finds host name among hosts.
    """
    result = []
    for host in hosts:
        if uuid_match(expr, host['key']) or \
                expr_match(expr, host['name']) or \
                expr_match(expr, host['hostname']):
            result.append(host)
    return result


def log_match(expr, log_item):
    """
    Returns true if the expression given matches the log. Expression is either
    a simple word or a regular expression if it starts with '/'.

    We perform the test on UUID, log name, and file name.
    """
    return uuid_match(expr, log_item['key']) or \
           expr_match(expr, log_item['name']) or \
           expr_match(expr, log_item['filename'])


def find_logs(expr, hosts):
    """
    Finds log name among hosts. The searching expression have to parts: host
    name and logs name. Both parts are divided by :.
    """
    # Decode expression
    split_expr = expr.find(':')
    if split_expr != -1:
        host_expr = expr[0:split_expr]
        log_expr = expr[split_expr + 1:]
    else:
        host_expr = '/.*'
        log_expr = expr

    adepts = find_hosts(host_expr, hosts)
    logs = []
    for host in adepts:
        for xlog in host['logs']:
            if log_match(log_expr, xlog):
                logs.append(xlog)
    return logs


def find_api_obj_by_name(obj_list, name):
    """
    Finds object in a list by its name parameter. List of objects must conform
    to that of a log or host entity from api.
    """
    result = None
    for obj in obj_list:
        if obj['name'] == name:
            result = obj
            break
    return result


def find_api_obj_by_key(obj_list, key):
    """
    Finds object in a list by its key parameter. List of objects must conform
    to that of a log or host entity from api.
    """
    result = None
    for obj in obj_list:
        if obj['key'] == key:
            result = obj
            break
    return result


def die(cause, exit_code=EXIT_ERR):
    log.critical('%s', cause)
    sys.exit(exit_code)


def error(cause, *args):
    die(red('Error:' + ' ' + cause % args))


def rfile(name):
    """
    Returns content of the file, without trailing newline.
    """
    content = open(name).read()
    if len(content) != 0 and content[-1] == '\n':
        content = content[0:len(content) - 1]
    return content


def rm_pidfile(config):
    """
    Removes PID file. Called when the agent exits.
    """
    try:
        if config.pid_file:
            os.remove(config.pid_file)
    except OSError:
        pass


def uuid_match(candidate, text):
    """
    Returns True if the uuid given is uuid and it matches to the text.
    """
    return is_uuid(candidate) and candidate == text


def is_uuid(candidate):
    """
    Returns true if the string given appears to be UUID.
    """
    return re.match(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        candidate)


def uuid_parse(text):
    """Returns uuid given or None in case of syntax error.
    """
    try:
        if FEAT_UUID:
            return uuid.UUID(text).__str__()
        else:
            low_text = text.lower()
            if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}',
                        low_text):
                return low_text
    except ValueError:
        pass
    return None

AUTHORITY_CERTIFICATE = ""


def get_bundled_certs():
    """Read contents of cacert.pem"""
    file_name = os.path.join(os.path.dirname(__file__), "cacert.pem")
    with open(file_name) as contents:
        return contents.read()


def print_usage(version_only=False):
    """Print usage"""
    if version_only:
        report(__version__)
    else:
        report(USAGE)

    sys.exit(EXIT_HELP)


def choose_account_key(accounts):
    """
    Allows user to select the right account.
    """
    if len(accounts) == 0:
        die('No account is associated with your profile. '
            'Log in to Logentries to create a new account.')
    if len(accounts) == 1:
        return accounts[0]['account_key']

    for i in range(0, len(accounts)):
        account = accounts[i]
        sys.stderr.write('[%s] %s %s' % (i, account['account_key'][:8], account['name']))

    while True:
        try:
            selection = int(input('Pick account you would like to use: '))
            if selection in range(0, len(accounts)):
                return accounts[selection]['account_key']
        except ValueError:
            pass
        sys.stderr.write('Invalid choice. Please try again or break with Ctrl+C.')


def print_total(elems, name):
    """
    Prints total number of elements in the list
    """
    total = len(elems)
    if total == 0:
        report("no %ss" % name)
    elif total == 1:
        report("1 " + name)
    else:
        report("%d %ss \n" % (total, name))


def retrieve_account_key(config):
    """
    Retrieves account keys from the web server.
    """
    while True:
        try:
            username = input('Email: ')
            password = getpass.getpass()
            c = domain_connect(config, Domain.MAIN, Domain)
            c.request('POST', ACCOUNT_KEYS_API,
                      urlencode({'username': username, 'password': password}),
                      {
                          'Referer': 'https://logentries.com/login/',
                          'Content-type': 'application/x-www-form-urlencoded',
                      })
            response = c.getresponse()
            if not response or response.status != 200:
                resp_val = 'err'
                if response:
                    resp_val = response.status
                if resp_val == 403:
                    sys.stderr.write('Error: Login failed. Invalid credentials.')
                else:
                    sys.stderr.write('Error: Unexpected login response from logentries (%s).'
                                     % resp_val)
            else:
                data = json.loads(response.read())
                return choose_account_key(data['accounts'])
        except socket.error as msg:
            sys.stderr.write('Error: Cannot contact server, %s' % msg)
        except ValueError as msg:
            sys.stderr.write('Error: Invalid response from the server (Parsing error %s)' % msg)
        except KeyError:
            sys.stderr.write('Error: Invalid response from the server, user key not present.')
        except EOFError:
            # Ctrl+D in get_pass, simulate Ctrl+C
            raise KeyboardInterrupt()

        sys.stderr.write('Try to log in again, or press Ctrl+C to break')

def safe_get(dct, *keys):
    """Gets a value from a dictionary if it exists."""
    for key in keys:
        try:
            dct = dct[key]
        except KeyError:
            return None
    return dct


def cmp(a, b):
    """
    Built-in cmp method is removed in python3
    """
    return (a > b) - (a < b)


def cmp_patterns(a, b):
    """
    Intuitive comparison of two patterns.
    """
    v = cmp(a['priority'], b['priority'])
    if v == 0:
        ap = a['pattern'].lower()
        if ap.endswith('/'):
            ap = ap[:-1]
        bp = b['pattern'].lower()
        if bp.endswith('/'):
            bp = bp[:-1]
        v = cmp(ap, bp)
    return v
