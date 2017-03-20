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
cat "$CONFIG" | grep Main
#o [Main]
cat "$CONFIG" | grep user-key
#o user-key = f720fe54-879a-11e4-81ac-277d856f873e
cat "$CONFIG" | grep agent-key
#o agent-key = 41ae887a-284a-4d78-91fe-56485b076148
cat "$CONFIG" | grep hostname
#o hostname = myhost
cat "$CONFIG" | grep metrics-swap
#o metrics-swap = system
cat "$CONFIG" | grep metrics-space
#o metrics-space = /
cat "$CONFIG" | grep metrics-token
#o metrics-token = 
cat "$CONFIG" | grep metrics-disk
#o metrics-disk = sum
cat "$CONFIG" | grep metrics-vcpu
#o metrics-vcpu = 
cat "$CONFIG" | grep metrics-interval
#o metrics-interval = 5s
cat "$CONFIG" | grep metrics-cpu
#o metrics-cpu = system
cat "$CONFIG" | grep metrics-net
#o metrics-net = sum
cat "$CONFIG" | grep metrics-mem
#o metrics-mem = system


Testcase 'Monitoring'

touch example.log
echo 'Skip this message' >> example.log
$LE --debug-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
LE_PID=$!

sleep 1
echo 'First message' >> example.log
echo 'Second message' >> example.log
sleep 1
#e
#e First message
#e Second message
#e Shutting down
