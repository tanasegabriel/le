"""Constants Module"""
#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:

from __init__ import __version__

NOT_SET = None

CORP = "logentries"

ACCOUNT_KEYS_API = '/agent/account-keys/'
ID_LOGS_API = '/agent/id-logs/'

LINE_SEPARATOR = '\xe2\x80\xa8'

# Maximal queue size for events sent
SEND_QUEUE_SIZE = 32000

# Logentries server details
LE_SERVER_API = '/'


# Structures embedded (beta)
EMBEDDED_STRUCTURES = {
    # JSON with support for nested objects
    "json": "444e607f-14bd-405e-a2ce-c4892b5a3b15",
    # General kvp parser
    "kvp": "380d3f36-1a8d-45ad-972f-3001768870ca",
    # Apache access log
    "http": "803fe7ba-bd2e-44bd-8ee7-f02fa253ef5f",
}

# '--multilog' option related
# Max number of files that are allowed to be followed at any one time
MAX_FILES_FOLLOWED = 100
# Prefix used to distinguish pathnames in config or server side
# as intended for mutlilog behaviour
PREFIX_MULTILOG_FILENAME = "Multilog:"
# Time interval to retry glob of multilog pathname to catch any
# change in relevant directories that may have been deleted or added
RETRY_GLOB_INTERVAL = 0.250 # in seconds
# Intervals for .join() on several threads
FOLLOWMULTI_JOIN_INTERVAL = 1.0  # in seconds
FOLLOWER_JOIN_INTERVAL = 1.0    # in seconds
TRANSPORT_JOIN_INTERVAL = 1.5   # in seconds

CONTENT_LENGTH = 'content-length'

# Log root directory
LOG_ROOT = '/var/log'

# Timeout after server connection fail. Might be a temporary network
# failure.
SRV_RECON_TIMEOUT = 10  # in seconds
SRV_RECON_TO_MIN = 1   # in seconds
SRV_RECON_TO_MAX = 10  # in seconds

# Timeout after invalid server response. Might be a version mishmash or
# temporary server/network failure
INV_SRV_RESP_TIMEOUT = 30  # Seconds

# Time interval between re-trying to open log file
REOPEN_TRY_INTERVAL = 1  # Seconds

# Number of lines which can be sent in one buck, piggybacking
MAX_LINES_SENT = 10

# Time in seconds spend between log re-checks
TAIL_RECHECK = 0.2  # Seconds

# Number of attemps to read a file, until the name is recheck
NAME_CHECK = 4  # TAIL_RECHECK cycles

# Interval of inactivity when IAA token is sent
IAA_INTERVAL = 10.0 # Seconds
# I am alive token that's passed at fixed interval during inactivity
IAA_TOKEN = "###LE-IAA###"

# Maximal size of a block of events
MAX_BLOCK_SIZE = 65536 - 512 # Space for formatting

# Interval between attampts to open a file
REOPEN_INT = 1  # Seconds

# Linux block devices
SYS_BLOCK_DEV = '/sys/block/'
# Linux CPU stat file
CPUSTATS_FILE = '/proc/stat'
# Linux mmeory stat file
MEMSTATS_FILE = '/proc/meminfo'
# Linux network stat file
NETSTATS_FILE = '/proc/net/dev'

# List of accepted network devices
NET_DEVICES = ['  eth', ' wlan', 'venet', ' veth']

EPOCH = 5  # in seconds

QUEUE_WAIT_TIME = 1  # time in seconds to wait for reading from the transport queue if it is empty


# File Handler Positions
FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

# Config response parameters
CONF_RESPONSE = 'response'
CONF_REASON = 'reason'
CONF_LOGS = 'logs'
CONF_SERVERS = 'servers'
CONF_OK = 'ok'

# Server requests
RQ_WORKLOAD = 'push_wl'

# Release information on LSB systems
LSB_RELEASE = '/etc/lsb-release'


#
# Usage help
#

PULL_USAGE = "pull <path> <when> <filter> <limit>"
PUSH_USAGE = "push <file> <path> <log-type>"
USAGE = "Logentries agent version " + __version__ + """
usage: le COMMAND [ARGS]

Where command is one of:
  init      Write local configuration file
  reinit    As init but does not reset undefined parameters
  register  Register this host
    --name=  name of the host
    --hostname=  hostname of the host
  whoami    Displays settings for this host
  monitor   Monitor this host
  follow <filename>  Follow the given log
    --name=  name of the log
    --type=  type of the log
    --multilog option used with directory wildcard * (restricted behaviour)
  followed <filename>  Check if the file is followed
  clean     Removes configuration file
  ls        List internal filesystem and settings: <path>
  rm        Remove entity: <path>
  pull      Pull log file: <path> <when> <filter> <limit>

Where parameters are:
  --help                  show usage help and exit
  --version               display version number and exit
  --config=               load specified configuration
  --config.d=             load configurations from directory
  --account-key=          set account key and exit
  --host-key=             set local host key and exit, generate key if key is empty
  --no-timestamps         no timestamps in agent reportings
  --force                 force given operation
  --suppress-ssl          do not use SSL with API server
  --yes                   always respond yes
  --datahub               send logs to the specified data hub address
                          the format is address:port with port being optional
  --system-stat-token=    set the token for system stats log (beta)
  --pull-server-side-config=False do not use server-side config for following files
"""

# Multilog option usage
MULTILOG_USAGE = \
"""
Usage:
  Agent is expecting a path name for a file, which should be between single quotes:
        example: \'/var/log/directoryname/file.log\'
  A * wildcard for expansion of directory name can be used. Only the one * wildcard is allowed.
  Wildcard can not be used for expansion of filename, but for directory name only.
  Place path name with wildcard between single quotes:
        example: \"/var/log/directory*/file.log\"
"""

# Identified ranges

SEC = 1000
MIN = 60 * SEC
HOUR = 60 * MIN
DAY = 24 * HOUR
MON = 31 * DAY
YEAR = 365 * DAY


LOG_LE_AGENT = 'logentries.com'


LE_CERT_NAME = 'ca-certs.pem'

TCP_TIMEOUT = 10  # TCP timeout for the socket in seconds


LOGSET_URL = "https://rest.logentries.com/management/logsets/"
LOG_URL = "https://rest.logentries.com/management/logs/"

#Return Codes
EXIT_OK = 0
EXIT_NO = 1
EXIT_ERR = 3
EXIT_HELP = 4
EXIT_TERMINATED = 5  # Terminated by user (Ctrl+C)

TOKEN_PARAM = 'token'
DESTINATION_PARAM = 'destination'
