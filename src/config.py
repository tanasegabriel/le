"""Config Module"""
#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:
# pylint: disable=too-many-instance-attributes, attribute-defined-outside-init

import os
import socket
import stat
import getopt
import configparser as ConfigParser

import metrics
import utils
from log import log
from configured_log import ConfiguredLog
from constants import NOT_SET, EXIT_OK, MULTILOG_USAGE, DESTINATION_PARAM, TOKEN_PARAM


DEFAULT_USER_KEY = NOT_SET
DEFAULT_AGENT_KEY = NOT_SET
PID_FILE = '/var/run/logentries.pid'
LE_CONFIG = 'config'  # Default configuration file
CONFIG_DIR_SYSTEM = '/etc/le'
CONFIG_DIR_USER = '.le'
CONF_SUFFIX = '.conf'  # Expected suffix of configuration files
LOCAL_CONFIG_DIR_USER = '.le'
LOCAL_CONFIG_DIR_SYSTEM = '/etc/le'
MAIN_SECT = 'Main'
USER_KEY_PARAM = 'user-key'
AGENT_KEY_PARAM = 'agent-key'
API_KEY_PARAM = 'api-key'
FILTERS_PARAM = 'filters'
FORMATTERS_PARAM = 'formatters'
FORMATTER_PARAM = 'formatter'
ENTRY_IDENTIFIER_PARAM = 'entry_identifier'
SUPPRESS_SSL_PARAM = 'suppress_ssl'
USE_CA_PROVIDED_PARAM = 'use_ca_provided'
FORCE_DOMAIN_PARAM = 'force_domain'
DATAHUB_PARAM = 'datahub'
SYSSTAT_TOKEN_PARAM = 'system-stat-token'
STATE_FILE_PARAM = 'state-file'
HOSTNAME_PARAM = 'hostname'
PATH_PARAM = 'path'
INCLUDE_PARAM = 'include'
PULL_SERVER_SIDE_CONFIG_PARAM = 'pull-server-side-config'
PROXY_TYPE_PARAM = "proxy-type"
PROXY_URL_PARAM = "proxy-url"
PROXY_PORT_PARAM = "proxy-port"
KEY_LEN = 36
LE_DEFAULT_SSL_PORT = 20000
LE_DEFAULT_NON_SSL_PORT = 10000


class FatalConfigurationError(Exception):
    """Fatal Config Error"""
    def __init__(self, msg):
        super(FatalConfigurationError, self).__init__(msg)



class Config(object):
    """Config class"""

    def __init__(self):
        self.config_dir_name = self._get_config_dir()
        self.config_filename = self.config_dir_name + LE_CONFIG
        self.config_d = os.path.join(self.config_dir_name, 'conf.d')
        self.include = NOT_SET

        # Configuration variables
        self.agent_key = NOT_SET
        self.api_key = NOT_SET
        self.suppress_ssl = False
        self.use_ca_provided = False
        self.user_key = DEFAULT_USER_KEY
        self.datahub = NOT_SET
        self.datahub_ip = NOT_SET
        self.datahub_port = NOT_SET
        self.system_stats_token = NOT_SET
        self.pull_server_side_config = NOT_SET
        self.configured_logs = []
        self.metrics = metrics.MetricsConfig()

        # Special options
        self.daemon = False
        self.filters = NOT_SET
        self.formatters = NOT_SET
        self.formatter = NOT_SET
        self.entry_identifier = NOT_SET
        self.force = False
        self.hostname = NOT_SET
        self.name = NOT_SET
        self.no_timestamps = False
        self.pid_file = PID_FILE
        self.std = False
        self.std_all = False
        self.system_stats_token = NOT_SET
        self.uuid = False
        self.xlist = False
        self.yes = False
        self.multilog = False
        self.state_file = NOT_SET
        # Behaviour associated with daemontools/multilog

        self._init_proxy()
        self._init_debug_options()

    def _init_proxy(self):
        """Initialize proxy config values"""
        self.use_proxy = NOT_SET
        self.proxy_type = NOT_SET
        self.proxy_url = NOT_SET
        self.proxy_port = NOT_SET

    def _init_debug_options(self):
        """Set Debug Options"""

        # Enabled fine-grained logging
        self.debug = False
        # Command line args to stderr
        self.debug_cmd_line = False
        # Multilog specific debugging to stderr
        self.debug_multilog = False
        # All recognized events are logged
        self.debug_events = False
        # All transported events are logged
        self.debug_transport_events = False
        # All filtering actions are logged
        self.debug_filters = False
        # All formattering actions are logged
        self.debug_formatters = False
        # All metrics actions are logged
        self.debug_metrics = False
        # Adapter connects to locahost
        self.debug_local = False
        # Do not collect statistics
        self.debug_nostats = False
        # Collected statistics are logged
        self.debug_stats = False
        # Collect statistics only
        self.debug_stats_only = False
        # Commands passed to server are logged
        self.debug_requests = False
        # Display system information and exit
        self.debug_system = False
        # Display list of logs in the system
        self.debug_loglist = False
        # Force host for api
        self.force_api_host = NOT_SET
        # Force host for data
        self.force_data_host = NOT_SET
        # Force host for this domain
        self.force_domain = NOT_SET

    def process_params(self, params): #pylint: disable=too-many-branches, too-many-statements
        """
        Parses command line parameters and updates config parameters accordingly
        """
        param_list = """user-key= account-key= agent-key= host-key= no-timestamps debug-events
                    debug-transport-events debug-metrics
                    debug-filters debug-formatters debug-loglist local debug-stats debug-nostats
                    debug-stats-only debug-cmd-line debug-system help version yes force uuid list
                    std std-all name= hostname= type= pid-file= debug no-defaults
                    suppress-ssl use-ca-provided force-api-host= force-domain=
                    system-stat-token= datahub=
                    pull-server-side-config= config= config.d= multilog debug-multilog"""
        try:
            optlist, args = getopt.gnu_getopt(params, '', param_list.split())
            for name, value in optlist:
                if name == "--help":
                    utils.print_usage()
                if name == "--version":
                    utils.print_usage(True)
                if name == "--config":
                    self.config_filename = value
                if name == "--config.d":
                    self.config_d = value
                if name == "--yes":
                    self.yes = True
                elif name == "--user-key":
                    self._set_user_key(value)
                elif name == "--account-key":
                    self._set_user_key(value)
                elif name == "--agent-key":
                    self._set_agent_key(value)
                elif name == "--host-key":
                    self._set_agent_key(value)
                elif name == "--force":
                    self.force = True
                elif name == "--list":
                    self.xlist = True
                elif name == "--uuid":
                    self.uuid = True
                elif name == "--name":
                    self.name = value
                elif name == "--hostname":
                    self.hostname = value
                elif name == "--pid-file":
                    if value == '':
                        self.pid_file = None
                    else:
                        self.pid_file = value
                elif name == "--std":
                    self.std = True
                elif name == "--type":
                    self.type_opt = value
                elif name == "--std-all":
                    self.std_all = True
                elif name == "--no-timestamps":
                    self.no_timestamps = True
                elif name == "--debug":
                    self.debug = True
                elif name == "--debug-cmd-line":
                    self.debug_cmd_line = True
                elif name == "--debug-multilog":
                    self.debug_multilog = True
                elif name == "--debug-events":
                    self.debug_events = True
                elif name == "--debug-transport-events":
                    self.debug_transport_events = True
                elif name == "--debug-filters":
                    self.debug_filters = True
                elif name == "--debug-formatters":
                    self.debug_formatters = True
                elif name == "--debug-metrics":
                    self.debug_metrics = True
                elif name == "--local":
                    self.debug_local = True
                elif name == "--debug-stats":
                    self.debug_stats = True
                elif name == "--debug-nostats":
                    self.debug_nostats = True
                elif name == "--debug-stats-only":
                    self.debug_stats_only = True
                elif name == "--debug-loglist":
                    self.debug_loglist = True
                elif name == "--debug-requests":
                    self.debug_requests = True
                elif name == "--debug-system":
                    self.debug_system = True
                elif name == "--suppress-ssl":
                    self.suppress_ssl = True
                elif name == "--force-api-host":
                    if value and value != '':
                        self.force_api_host = value
                elif name == "--force-data-host":
                    if value and value != '':
                        self.force_data_host = value
                elif name == "--force-domain":
                    if value and value != '':
                        self.force_domain = value
                elif name == "--use-ca-provided":
                    self.use_ca_provided = True
                elif name == "--system-stat-token":
                    self._set_system_stat_token(value)
                elif name == "--pull-server-side-config":
                    self.pull_server_side_config = value == "True"
                elif name == "--datahub":
                    self._set_datahub_settings(value)
                elif name == "--multilog":
                    # self.multilog is only True if pathname is good
                    self.multilog = self.validate_pathname(args, True, None)

            if self.datahub_ip and not self.datahub_port:
                if self.suppress_ssl:
                    self.datahub_port = LE_DEFAULT_NON_SSL_PORT
                else:
                    self.datahub_port = LE_DEFAULT_SSL_PORT

            if self.debug_local and self.force_api_host:
                utils.die("Do not specify --local and --force-api-host at the same time.")
            if self.debug_local and self.force_data_host:
                utils.die("Do not specify --local and --force-data-host at the same time.")
            if self.debug_local and self.force_domain:
                utils.die("Do not specify --local and --force-domain at the same time.")
            return args

        except getopt.GetoptError as error:
            utils.die("Parameter error: " + str(error))

    def clean(self):
        """
        Wipes out old configuration file. Returns True if successful.
        """
        try:
            os.remove(self.config_filename)
        except OSError as error:
            if error.errno != 2:
                log.log.warning("Error: %s: %s", self.config_filename, error.strerror)
                return False
        return True

    def load(self, load_include_dirs=True):
        """
        Initializes configuration parameters from the configuration
        file.  Returns True if successful, False otherwise. Does not
        touch already defined parameters.

        Args:
          load_include_dirs (bool): specify if files from the include
                                    directory are loaded
        """

        try:
            conf = ConfigParser.SafeConfigParser({
                USER_KEY_PARAM: '',
                AGENT_KEY_PARAM: '',
                API_KEY_PARAM: '',
                FILTERS_PARAM: '',
                FORMATTERS_PARAM: '',
                FORMATTER_PARAM: '',
                ENTRY_IDENTIFIER_PARAM: '',
                SUPPRESS_SSL_PARAM: '',
                FORCE_DOMAIN_PARAM: '',
                USE_CA_PROVIDED_PARAM: '',
                DATAHUB_PARAM: '',
                SYSSTAT_TOKEN_PARAM: '',
                STATE_FILE_PARAM: '',
                HOSTNAME_PARAM: '',
                PULL_SERVER_SIDE_CONFIG_PARAM: 'True',
                INCLUDE_PARAM: '',
                PROXY_TYPE_PARAM: '',
                PROXY_URL_PARAM: '',
                PROXY_PORT_PARAM: '',
            })

            # Read configuration files from default directories
            config_files = [self.config_filename]
            if load_include_dirs:
                config_files.extend(self._list_configs(self.config_d))

            self._set_config_file_perms(config_files)

            conf.read(config_files)

            # Fail if no configuration file exist
            if not conf.has_section(MAIN_SECT):
                return False

            # Get optional user-provided configuration directory
            self.include = self._get_if_def(conf, self.include, INCLUDE_PARAM)

            # Load configuration files from user-provided directory
            if load_include_dirs and self.include:
                config_files.extend(conf.read(self._list_configs(self.include)))

            log.log.debug('Configuration files loaded: %s', ', '.join(config_files))

            self._load_parameters(conf)

            self._configure_proxy(conf)

            new_suppress_ssl = conf.get(MAIN_SECT, SUPPRESS_SSL_PARAM)
            if new_suppress_ssl == 'True':
                self.suppress_ssl = new_suppress_ssl == 'True'
            new_force_domain = conf.get(MAIN_SECT, FORCE_DOMAIN_PARAM)
            if new_force_domain:
                self.force_domain = new_force_domain
            if self.datahub == NOT_SET:
                self._set_datahub_settings(
                    conf.get(MAIN_SECT, DATAHUB_PARAM), should_die=False)
            if self.system_stats_token == NOT_SET:
                system_stats_token_str = conf.get(
                    MAIN_SECT, SYSSTAT_TOKEN_PARAM)
                if system_stats_token_str != '':
                    self.system_stats_token = system_stats_token_str
            if self.state_file == NOT_SET:
                state_file_str = conf.get(MAIN_SECT, STATE_FILE_PARAM)
                if state_file_str:
                    self.state_file = state_file_str

            self.metrics.load(conf)

            self._load_configured_logs(conf)

        except (ConfigParser.NoSectionError,
                ConfigParser.NoOptionError,
                ConfigParser.MissingSectionHeaderError) as error:
            raise FatalConfigurationError('%s' % error)
        return True

    def save(self):  # pylint: disable=too-many-branches
        """
        Saves configuration parameters into the configuration file.
        The file with certificates is added as well.
        """
        try:
            conf = ConfigParser.SafeConfigParser()
            utils.create_conf_dir(self)
            conf_file = open(self.config_filename, 'wb')
            conf.add_section(MAIN_SECT)
            if self.user_key != NOT_SET:
                conf.set(MAIN_SECT, USER_KEY_PARAM, self.user_key)
            if self.agent_key != NOT_SET:
                conf.set(MAIN_SECT, AGENT_KEY_PARAM, self.agent_key)
            if self.api_key != NOT_SET:
                conf.set(MAIN_SECT, API_KEY_PARAM, self.api_key)
            if self.filters != NOT_SET:
                conf.set(MAIN_SECT, FILTERS_PARAM, self.filters)
            if self.formatters != NOT_SET:
                conf.set(MAIN_SECT, FORMATTERS_PARAM, self.formatters)
            if self.formatter != NOT_SET:
                conf.set(MAIN_SECT, FORMATTER_PARAM, self.formatter)
            if self.hostname != NOT_SET:
                conf.set(MAIN_SECT, HOSTNAME_PARAM, self.hostname)
            if self.suppress_ssl:
                conf.set(MAIN_SECT, SUPPRESS_SSL_PARAM, 'True')
            if self.use_ca_provided:
                conf.set(MAIN_SECT, USE_CA_PROVIDED_PARAM, 'True')
            if self.force_domain:
                conf.set(MAIN_SECT, FORCE_DOMAIN_PARAM, self.force_domain)
            if self.pull_server_side_config != NOT_SET:
                conf.set(MAIN_SECT, PULL_SERVER_SIDE_CONFIG_PARAM, "%s" %
                         self.pull_server_side_config)
            if self.datahub != NOT_SET:
                conf.set(MAIN_SECT, DATAHUB_PARAM, self.datahub)
            if self.system_stats_token != NOT_SET:
                conf.set(
                    MAIN_SECT, SYSSTAT_TOKEN_PARAM, self.system_stats_token)

            for clog in self.configured_logs:
                conf.add_section(clog.name)
                if clog.token:
                    conf.set(clog.name, TOKEN_PARAM, clog.token)
                conf.set(clog.name, PATH_PARAM, clog.path)
                if clog.destination:
                    conf.set(clog.name, DESTINATION_PARAM, clog.destination)

            self.metrics.save(conf)

            try:
                conf.write(str.encode(conf_file))
            except TypeError:
                conf.write(conf_file)


        except IOError as error:
            utils.die("Error: IO error when writing to config file: %s" % error)

    def user_key_required(self, ask_for_it):
        """
        Exits with error message if the user key is not defined.
        """
        if self.user_key == NOT_SET:
            if ask_for_it:
                log.log.info(
                    "Account key is required. Enter your Logentries login "
                    "credentials or specify the account key with "
                    "--account-key parameter.")
                self.user_key = utils.retrieve_account_key(self)
            else:
                utils.die("Account key is required. "
                          "Enter your account key with --account-key parameter.")
            self.save()

    def agent_key_required(self):
        """Exits with error message if the agent key is not defined.
        """
        if self.agent_key == NOT_SET:
            utils.die("Host key is required. "
                      "Register the host or specify the host key with the --host-key parameter.")

    def api_key_required(self):
        """Exits with error message if the API key is not defined.
        """
        if self.api_key == NOT_SET:
            utils.die("API key is required.")

    def hostname_required(self):
        """
        Sets the hostname parameter based on server network name. If
        the hostname is set already, it is kept untouched.
        """
        if self.hostname == NOT_SET:
            self.hostname = socket.getfqdn()
        return self.hostname

    def name_required(self):
        """
        Sets host name if not set already. The new host name is
        delivered from its hostname. As a side effect this
        function sets a hostname as well.
        """
        if self.name == NOT_SET:
            self.name = self.hostname_required().split('.')[0]
        return self.name

    @staticmethod
    def validate_pathname(args=None, cmd_line=True, path=None):
        """
        For the '--multilog' option where a wildcard can be used in the directory name.
        Validates the string that is passed to the agent from command line, config file or server.
        If error from command line, then error message written to command line and agent quits.
        If an error arises from the config file (or server) then the error message will be
        written to log and False is returned

        :return:    True if okay, the agent will die otherwise
        """
        pname = None
        if cmd_line and path is None and args is not None:
            pname_slice = args[1:]
            # Validate that a pathname is detected in parameters to agent
            if len(pname_slice) == 0:
                utils.die("\nError: No pathname detected - "
                          "Specify the path to the file to be followed\n"
                          + MULTILOG_USAGE, EXIT_OK)
            # Validate that agent is not receiving a list of pathnames
            # (possibly shell is expanding wildcard)
            elif len(pname_slice) > 1:
                utils.die("\nError: Too many arguments being passed to agent\n"
                          + MULTILOG_USAGE, EXIT_OK)
            pname = str(pname_slice[0])
        elif not cmd_line and path is None:
            # For anything not coming in on command line no output is written to command line
            log.log.error("Error: Pathname argument is empty")
            return False
        elif not cmd_line and path is not None:
            pname = path
        filename = os.path.basename(pname)
        # Verify there is a filename
        if not filename:
            if not cmd_line:
                log.log.error("Error: No filename detected in the pathname")
                return False
            else:
                utils.die("\nError: No filename detected - "
                          "Specify the filename to be followed\n" + MULTILOG_USAGE, EXIT_OK)
        # Check if a wildcard detected in pathname
        if '*' in pname:
            # Verify that only one wildcard is in pathname
            if pname.count('*') > 1:
                if not cmd_line:
                    log.log.error("Error: More then one wildcard * detected in pathname")
                    return False
                else:
                    utils.die("\nError: Only one wildcard * allowed\n" + MULTILOG_USAGE, EXIT_OK)
            # Verify that no wildcard is in filename
            if '*' in filename:
                if not cmd_line:
                    log.log.error("Error: Wildcard detected in filename of path argument")
                    return False
                else:
                    utils.die("\nError: No wildcard * allowed in filename\n"
                              + MULTILOG_USAGE, EXIT_OK)
        return True

    @staticmethod
    def _get_config_dir():
        """
        Identifies a configuration directory for the current user.
        Always terminated with slash.
        """
        if os.geteuid() == 0:
            # Running as root
            c_dir = CONFIG_DIR_SYSTEM
        else:
            # Running as an ordinary user
            c_dir = os.path.expanduser('~') + '/' + CONFIG_DIR_USER

        return c_dir + '/'

    @staticmethod
    def _list_configs(path):
        """
        Returns a list of configuration files located in the path.
        """
        configs = []
        for root, _, files in os.walk(path):
            for filename in files:
                if filename.endswith(CONF_SUFFIX):
                    configs.append(os.path.join(root, filename))
        return sorted(configs)

    @staticmethod
    def _get_if_def(conf, param, param_name):
        if param == NOT_SET:
            new_param = conf.get(MAIN_SECT, param_name)
            if new_param != '':
                return new_param
        return param

    @staticmethod
    def _check_key(key):
        """
        Checks if the key looks fine
        """
        return len(key) == KEY_LEN

    def _load_parameters(self, conf):
        """Load parameters from config file provided"""
        self.user_key = self._get_if_def(conf, self.user_key, USER_KEY_PARAM)
        self.agent_key = self._get_if_def(conf, self.agent_key, AGENT_KEY_PARAM)
        self.api_key = self._get_if_def(conf, self.api_key, API_KEY_PARAM)
        self.filters = self._get_if_def(conf, self.filters, FILTERS_PARAM)
        self.formatters = self._get_if_def(conf, self.formatters, FORMATTERS_PARAM)
        self.formatter = self._get_if_def(conf, self.formatter, FORMATTER_PARAM)
        self.entry_identifier = self._get_if_def(
            conf, self.entry_identifier, ENTRY_IDENTIFIER_PARAM)
        self.hostname = self._get_if_def(conf, self.hostname, HOSTNAME_PARAM)
        if self.pull_server_side_config == NOT_SET:
            new_pull_server_side_config = conf.get(MAIN_SECT, PULL_SERVER_SIDE_CONFIG_PARAM)
            self.pull_server_side_config = new_pull_server_side_config == 'True'
            if new_pull_server_side_config is None:
                self.pull_server_side_config = True

    def _configure_proxy(self, conf):
        """Load proxy configuration settings from config file provided"""
        if self.proxy_type is NOT_SET:
            self.proxy_type = conf.get(MAIN_SECT, PROXY_TYPE_PARAM)
            if not self.proxy_type:
                self.proxy_type = NOT_SET
        if self.proxy_url is NOT_SET:
            self.proxy_url = conf.get(MAIN_SECT, PROXY_URL_PARAM)
            if not self.proxy_url:
                self.proxy_url = NOT_SET
        if self.proxy_port is NOT_SET:
            proxy_port = conf.get(MAIN_SECT, PROXY_PORT_PARAM)
            if not proxy_port:
                self.proxy_port = NOT_SET
            else:
                self.proxy_port = int(proxy_port)

        self.use_proxy = self.proxy_type and self.proxy_url and self.proxy_port

    def _set_config_file_perms(self, config_files):
        """Adjust configuration file permissions to be only readable by owner + group"""
        for _config in config_files:
            try:
                if not os.path.exists(_config):
                    continue

                world_readable = bool(os.stat(_config).st_mode & stat.S_IROTH)
                if world_readable:
                    os.chmod(_config, 0o0640)
            except OSError:
                log.log.warn('Could not adjust permissions for config file %s',
                             _config, exc_info=True)

    def _load_configured_logs(self, conf):
        """
        Loads configured logs from the configuration file.
        These are logs that use tokens.
        """
        self.configured_logs = []

        for name in conf.sections():
            if name != MAIN_SECT:
                token = ''
                try:
                    xtoken = conf.get(name, TOKEN_PARAM)
                    if xtoken:
                        token = utils.uuid_parse(xtoken)
                        if not token:
                            log.log.warning("Invalid log token `%s' in application `%s'.",
                                            xtoken, name)
                except ConfigParser.NoOptionError:
                    pass

                try:
                    path = conf.get(name, PATH_PARAM)
                except ConfigParser.NoOptionError:
                    log.log.debug("Not following logs for application `%s' as `%s' "
                                  "parameter is not specified", name, PATH_PARAM)
                    continue

                destination = self._try_load_param(conf, name, DESTINATION_PARAM)
                formatter = self._try_load_param(conf, name, FORMATTER_PARAM)
                entry_identifier = self._try_load_param(conf, name, ENTRY_IDENTIFIER_PARAM)

                configured_log = ConfiguredLog(name, token,
                                               destination, path, formatter, entry_identifier)
                self.configured_logs.append(configured_log)

    def _try_load_param(self, conf, name, key):
        """Try to load a given parameter"""
        try:
            param = conf.get(name, key)
            return param
        except ConfigParser.NoOptionError:
            return ''

    def _set_user_key(self, value):
        if not self._check_key(value):
            utils.die('Error: User key does not look right.')
        self.user_key = value

    def _set_system_stat_token(self, value):
        """Set the system stat token withe the value provided"""
        if not self._check_key(value):
            utils.die('Error: system stat token does not look right.')
        self.system_stats_token = value

    def _set_agent_key(self, value):
        """Set agent key to value provided"""
        if not self._check_key(value):
            utils.die('Error: Agent key does not look right.')
        self.agent_key = value

    def _set_api_key(self, value):
        """Set the api key to the value provided"""
        if not self._check_key(value):
            utils.die('Error: API key does not look right.')
        self.api_key = value

    def _set_datahub_settings(self, value, should_die=True):
        """Set datahub settings"""
        if not value and should_die:
            utils.die('--datahub requires a parameter')
        elif not value and not should_die:
            return

        values = value.split(":")
        if len(values) > 2:
            utils.die("Cannot parse %s for --datahub. "
                      "Expected format: hostname:port" % value)

        self.datahub_ip = values[0]
        if len(values) == 2:
            try:
                self.datahub_port = int(values[1])
            except ValueError:
                utils.die("Cannot parse %s as port. "
                          "Specify a valid --datahub address" % values[1])
        self.datahub = value
