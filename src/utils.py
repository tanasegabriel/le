
# coding: utf-8
# vim: set ts=4 sw=4 et:

import errno
import httplib
import os
import re
import socket
import sys
try:
    import uuid
    FEAT_UUID = True
except ImportError:
    FEAT_UUID = False
from backports import match_hostname, CertificateError

import logging


__author__ = 'Logentries'

__all__ = ["EXIT_OK", "EXIT_NO", "EXIT_HELP", "EXIT_ERR", "EXIT_TERMINATED",
           "ServerHTTPSConnection", "LOG_LE_AGENT", "create_conf_dir",
           "default_cert_file", "system_cert_file", "domain_connect",
           "no_more_args", "find_hosts", "find_logs", "find_api_obj_by_key", "find_api_obj_by_name", "die",
           "rfile", 'TCP_TIMEOUT', "rm_pidfile", "set_proc_title", "uuid_parse", "report"]

# Return codes
EXIT_OK = 0
EXIT_NO = 1
EXIT_ERR = 3
EXIT_HELP = 4
EXIT_TERMINATED = 5  # Terminated by user (Ctrl+C)

LE_CERT_NAME = 'ca-certs.pem'

TCP_TIMEOUT = 10  # TCP timeout for the socket in seconds


authority_certificate_files = [  # Debian 5.x, 6.x, 7.x, Ubuntu 9.10, 10.4, 13.0
                                 "/etc/ssl/certs/ca-certificates.crt",
                                 # Fedora 12, Fedora 13, CentOS 5
                                 "/usr/share/purple/ca-certs/GeoTrust_Global_CA.pem",
                                 # Amazon AMI, CentOS 7, recent RHs
                                 "/etc/pki/tls/certs/ca-bundle.crt",
                                 # FreeBSD 10.2
                                 "/etc/ssl/cert.pem",
]

LOG_LE_AGENT = 'logentries.com'

log = logging.getLogger(LOG_LE_AGENT)

try:
    import ssl

    wrap_socket = ssl.wrap_socket
    FEAT_SSL = True
    try:
        ssl.create_default_context
        FEAT_SSL_CONTEXT = True
    except AttributeError:
        FEAT_SSL_CONTEXT = False
except ImportError:
    FEAT_SSL = False
    FEAT_SSL_CONTEXT = False

    def wrap_socket(sock, ca_certs=None, cert_reqs=None):
        return socket.ssl(sock)

def report(what):
    print >> sys.stderr, what

class ServerHTTPSConnection(httplib.HTTPSConnection):

    """
    A slight modification of HTTPSConnection to verify the certificate
    """

    def __init__(self, config, server, port, cert_file):
        self.no_ssl = config.suppress_ssl or not FEAT_SSL
        if self.no_ssl:
            if config.use_proxy == True:
                httplib.HTTPSConnection.__init__(self, config.proxy_url, config.proxy_port, context=context)
                if hasattr(httplib.HTTPSConnection, "set_tunnel"):
                    httplib.HTTPSConnection.set_tunnel(self, server, port)
                else:
                    httplib.HTTPSConnection._set_tunnel(self, server, port)
            else:
                httplib.HTTPSConnection.__init__(self, server, port)
        else:
            self.cert_file = cert_file
            if FEAT_SSL_CONTEXT:
                context = ssl.create_default_context(cafile=cert_file)
                if config.use_proxy == True:
                    httplib.HTTPSConnection.__init__(self, config.proxy_url, config.proxy_port, context=context)
                    if hasattr(httplib.HTTPSConnection, "set_tunnel"):
                        httplib.HTTPSConnection.set_tunnel(self, server, port)
                    else:
                        httplib.HTTPSConnection._set_tunnel(self, server, port)
                else:
                    httplib.HTTPSConnection.__init__(self, server, port, context=context)
            else:
                if config.use_proxy == True:
                    httplib.HTTPSConnection.__init__(self, config.proxy_url, config.proxy_port, cert_file=cert_file)
                    if hasattr(httplib.HTTPSConnection, "set_tunnel"):
                        httplib.HTTPSConnection.set_tunnel(self, server, port)
                    else:
                        httplib.HTTPSConnection._set_tunnel(self, server, port)
                else:
                    httplib.HTTPSConnection.__init__(self, server, port, cert_file=cert_file)

    def connect(self):
        if FEAT_SSL_CONTEXT:
            httplib.HTTPSConnection.connect(self)
        else:
            if self.no_ssl:
                return httplib.HTTPSConnection.connect(self)
            sock = create_connection(self.host, self.port)
            try:
                if self._tunnel_host:
                    self.sock = sock
                    self._tunnel()
            except AttributeError:
                pass
            self.sock = wrap_socket(
                sock, ca_certs=self.cert_file, cert_reqs=ssl.CERT_REQUIRED)
            try:
                match_hostname(self.sock.getpeercert(), self.host)
            except CertificateError, ce:
                die("Could not validate SSL certificate for %s: %s" % (
                    self.host, ce.message))


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
    except OSError, e:
        if e.errno != errno.EEXIST:
            if e.errno == errno.EACCES:
                die("You don't have permission to create logentries config file. Please run logentries agent as root.")
            die('Error: %s' % e)


def write_default_cert_file(config, authority_certificate):
    """
    Writes default certificate file in the configuration directory.
    """
    create_conf_dir(config)
    cert_filename = default_cert_file_name(config)
    f = open(cert_filename, 'wb')
    f.write(get_bundled_certs())
    f.close()


def default_cert_file(config):
    """
    Returns location of the default certificate file or None. It tries to write the
    certificate file if it is not there or it is outdated.
    """
    cert_filename = default_cert_file_name(config)
    try:
        # If the certificate file is not there, create it
        if not os.path.exists(cert_filename):
            write_default_cert_file(config, authority_certificate)
            return cert_filename

        # If it is there, check if it is outdated
        curr_cert = rfile(cert_filename)
        if curr_cert != authority_certificate:
            write_default_cert_file(config, authority_certificate)
    except IOError:
        # Cannot read/write certificate file, ignore
        return None
    return cert_filename


def system_cert_file():
    """
    Finds the location of our lovely site's certificate on the system or None.
    """
    for f in authority_certificate_files:
        if os.path.exists(f):
            return f
    return None


def create_connection(host, port):
    """
    A simplified version of socket.create_connection from Python 2.6.
    """
    for addr_info in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, stype, proto, cn, sa = addr_info
        soc = None
        try:
            soc = socket.socket(af, stype, proto)
            soc.settimeout(TCP_TIMEOUT)
            soc.connect(sa)
            return soc
        except socket.error:
            if socket:
                soc.close()

    raise socket.error, "Cannot make connection to %s:%s" % (host, port)


def make_https_connection(config, s, port):
    """
    Makes HTTPS connection. Tried all available certificates.
    """
    if not config.use_ca_provided:
        # Try to connect with system certificate
        try:
            cert_file = system_cert_file()
            if cert_file:
                return ServerHTTPSConnection(config, s, port, cert_file)
        except socket.error, e:
            pass

    # Try to connect with our default certificate
    cert_file = default_cert_file(config)
    if not cert_file:
        die('Error: Cannot find suitable CA certificate.')
    return ServerHTTPSConnection(config, s, port, cert_file)


def domain_connect(config, domain, Domain):
    """
    Connects to the domain specified.
    """
    # Find the correct server address
    s = domain
    if Domain == Domain.API:
        if config.force_domain:
            s = config.force_domain
        elif config.force_api_host:
            s = config.force_api_host
        else:
            s = Domain.API

    # Special case for local debugging
    if config.debug_local:
        if s == Domain.API:
            s = Domain.API_LOCAL
        else:
            s = Domain.MAIN_LOCAL

    # Determine if to use SSL for connection
    # Never use SSL for debugging, always use SSL with main server
    use_ssl = True
    if config.debug_local:
        use_ssl = False
    elif s == Domain.API:
        use_ssl = not config.suppress_ssl

    # Connect to server with SSL in untrusted network
    if use_ssl:
        port = 443
    else:
        port = 80
    if config.debug_local:
        if s == Domain.API:
            port = 8000
        else:
            port = 8081
    log.debug('Connecting to %s:%s', s, port)

    # Pass the connection
    if use_ssl:
        return make_https_connection(config, s, port)
    else:
        if config.use_proxy == True:
            conn = httplib.HTTPConnection(config.proxy_url, config.proxy_port)
            if hasattr(httplib.HTTPConnection, "set_tunnel"):
                conn.set_tunnel(s, port)
            else:
                conn._set_tunnel(s, port)
            return conn
        else:
            return httplib.HTTPConnection(s, port)



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
        if uuid_match(expr, host['key']) or expr_match(expr, host['name']) or expr_match(expr, host['hostname']):
            result.append(host)
    return result


def log_match(expr, log_item):
    """
    Returns true if the expression given matches the log. Expression is either
    a simple word or a regular expression if it starts with '/'.

    We perform the test on UUID, log name, and file name.
    """
    return uuid_match(
        expr, log_item['key']) or expr_match(expr, log_item['name']) or expr_match(expr,
                                                                                   log_item['filename'])


def find_logs(expr, hosts):
    """
    Finds log name among hosts. The searching expresion have to parts: host
    name and logs name. Both parts are divided by :.
    """
    # Decode expression
    l = expr.find(':')
    if l != -1:
        host_expr = expr[0:l]
        log_expr = expr[l + 1:]
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
    log.critical(cause)
    sys.exit(exit_code)


def rfile(name):
    """
    Returns content of the file, without trailing newline.
    """
    x = open(name).read()
    if len(x) != 0 and x[-1] == '\n':
        x = x[0:len(x) - 1]
    return x


def rm_pidfile(config):
    """
    Removes PID file. Called when the agent exits.
    """
    try:
        if config.pid_file:
            os.remove(config.pid_file)
    except OSError:
        pass


def set_proc_title(title):
    try:
        import setproctitle
        setproctitle.setproctitle(title)
    except ImportError:
        pass


def uuid_match(uuid, text):
    """
    Returns True if the uuid given is uuid and it matches to the text.
    """
    return is_uuid(uuid) and uuid == text


def is_uuid(x):
    """
    Returns true if the string given appears to be UUID.
    """
    return re.match(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', x)


def uuid_parse(text):
    """Returns uuid given or None in case of syntax error.
    """
    try:
        if FEAT_UUID:
            return uuid.UUID(text).__str__()
        else:
            low_text = text.lower()
            if re.match( r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', low_text):
                return low_text
    except ValueError:
        pass
    return None

authority_certificate = ""


def get_bundled_certs():
    file_name = os.path.join(os.path.dirname(__file__), "cacert.pem")
    with open(file_name) as r:
        return r.read()
