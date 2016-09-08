#!/bin/bash

. vars

#
# Basic workflow: Setting up configuration, monitoring, sending sample data
#

Scenario 'Basic workflow with client-side configured logs'

Testcase 'Init'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

echo 'pull-server-side-config = False' >>"$CONFIG"
echo '[Web]' >>"$CONFIG"
echo 'token = 0b52788c-7981-4138-ac40-6720ae2d5f0c' >>"$CONFIG"
echo "path = $TMP/example.log" >>"$CONFIG"
cat "$CONFIG"
#o [Main]
#o user-key = f720fe54-879a-11e4-81ac-277d856f873e
#o agent-key = 41ae887a-284a-4d78-91fe-56485b076148
#o hostname = myhost
#o metrics-mem = system
#o metrics-token = 
#o metrics-disk = sum
#o metrics-swap = system
#o metrics-space = /
#o metrics-vcpu = 
#o metrics-net = sum
#o metrics-interval = 5s
#o metrics-cpu = system
#o
#o pull-server-side-config = False
#o [Web]
#o token = 0b52788c-7981-4138-ac40-6720ae2d5f0c
#o path = $TMP/example.log

Testcase 'Monitoring'

touch example.log
echo 'Skip this message' >> example.log
$LE --debug-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
#e Opening connection 127.0.0.1:10000 
LE_PID=$!

sleep 1
echo 'First message' >> example.log
echo 'Second message' >> example.log
sleep 1

#e First message
#e Second message

kill $LE_PID

