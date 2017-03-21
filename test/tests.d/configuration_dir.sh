#!/bin/bash

. vars

Scenario 'Configuration directory'

Testcase 'Recognizes configuration directory provided on command line'

mkdir $CONFIG_D
touch $CONFIG_D/abraka.conf # Accepted
touch $CONFIG_D/braka # Ignored - does not have .conf extension
$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY
#e Initialized

$LE ls
#e Configuration files loaded: sandbox_config, sandbox_config.d/abraka.conf
#o apps
#o clusters
#o hostnames
#o hosts
#o logs
#o logtypes
#e Connecting to 127.0.0.1:8081
#e Domain request: GET /f720fe54-879a-11e4-81ac-277d856f873e/ None {}
#e List response: {"object": "rootlist", "list": [{"name": "logs", "key": ""}, {"name": "hosts", "key": ""}, {"name": "hostnames", "key": ""}, {"name": "apps", "key": ""}, {"name": "clusters", "key": ""}, {"name": "logtypes", "key": ""}], "response": "ok"}
#e 6 items

Testcase 'Recognizes configuration directory from main configuration'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY
#e Initialized

mkdir special.d
touch special.d/foo.conf
tee >>$CONFIG <<EOF
include=special.d
EOF

$LE ls
#e Configuration files loaded: sandbox_config, sandbox_config.d/abraka.conf, special.d/foo.conf
#o apps
#o clusters
#o hostnames
#o hosts
#o logs
#o logtypes
#e Connecting to 127.0.0.1:8081
#e Domain request: GET /f720fe54-879a-11e4-81ac-277d856f873e/ None {}
#e List response: {"object": "rootlist", "list": [{"name": "logs", "key": ""}, {"name": "hosts", "key": ""}, {"name": "hostnames", "key": ""}, {"name": "apps", "key": ""}, {"name": "clusters", "key": ""}, {"name": "logtypes", "key": ""}], "response": "ok"}
#e 6 items


Testcase 'The reinit command does not load configuration from directories'

##$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY
##e Initialized

$LE reinit --pull-server-side-config=False --suppress-ssl --datahub="127.0.0.1:10000" --hostname "abarakedabra"
#e Configuration files loaded: sandbox_config
#e Reinitialized

Scenario 'Handle gracefully missing section in configuration file'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY
#e Initialized

echo 'abraka' >>$CONFIG_D/foo.conf

$LE ls
#e Fatal: File contains no section headers.
#e file: 'sandbox_config.d/foo.conf', line: 1
#e 'abraka\n'
