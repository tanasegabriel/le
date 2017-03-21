#!/bin/bash

. vars

Scenario 'Recognizes layered configuration directories'

mkdir $CONFIG_D
mkdir $CONFIG_D/A
mkdir $CONFIG_D/A/B
mkdir $CONFIG_D/C
mkdir $CONFIG_D/D
touch $CONFIG_D/a.conf # Basic
touch $CONFIG_D/A/a.conf # Layered
touch $CONFIG_D/A/B/b.conf # Event more layered
touch $CONFIG_D/C/c.conf # Layered
$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY
#e Initialized

$LE ls
#e Configuration files loaded: sandbox_config, sandbox_config.d/A/B/b.conf, sandbox_config.d/A/a.conf, sandbox_config.d/C/c.conf, sandbox_config.d/a.conf
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

