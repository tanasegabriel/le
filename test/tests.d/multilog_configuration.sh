#!/bin/bash

. vars

#############                                                      ##############
#       "multilog configuration"                                                #
#       Test Scope: Use of client configuration file with a multilog            # 
#       wildcard pathname for monitoring of files.                              #
#                                                                               #
#############                                                      ##############

Scenario 'Using client side configuration with multilog pathname'

Testcase 'init and set client configuration with wildcard in multilog pathname'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_MULTILOG_KEY
#e Initialized

echo 'pull-server-side-config = False' >>"$CONFIG"
echo '[Apache]' >>"$CONFIG"
echo 'token = 0b52788c-7981-4138-ac40-6720ae2d5f0c' >>"$CONFIG"
echo "path = Multilog:$TMP/apache*/current" >>"$CONFIG"
cat "$CONFIG" | grep path
#o path = Multilog:$TMP/apache*/current

Testcase 'Monitoring file in multiple directories'

mkdir apache-01
touch apache-01/current
mkdir apache-02
touch apache-02/current
mkdir apache-03
touch apache-03/current

$LE --debug-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/apache*/current
LE_PID=$!

sleep 1
echo 'First message' >> apache-01/current
sleep 1
#e
#e First message
echo 'Second message' >> apache-02/current
sleep 1
#e Second message
echo 'Third message' >> apache-03/current
#e Third message
sleep 1

# tidy up test directory and daemon
rm -rf apache*

#e Shutting down

