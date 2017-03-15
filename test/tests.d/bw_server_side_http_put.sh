#!/bin/bash

. vars

#
# Basic workflow: registering, server-side configuration, monitoring, sending sample data
#

Scenario 'Basic workflow'

Testcase 'Init'

$LE init --account-key=$ACCOUNT_KEY
#e Initialized

cat $CONFIG
#o [Main]879a-11e4-81ac-277d856f873e
#o user-key = f720fe54-
#o api-key = 459c6737-375a-447b-aa2a-56cd1400a34c
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

Testcase 'Register'

$LE register --name Name --hostname Hostname
#e Registered Name (Hostname)

Testcase 'Follow'

touch example.log example2.log
$LE follow example.log
#e Already following $TMP/example.log


echo 'Skip this message' >> example.log

Testcase 'Monitoring'

$LE --debug-events monitor &
#e Following $TMP/example.log
#e Opening connection 127.0.0.1:8081 PUT /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/400da462-36fa-48f4-bb4e-87f96ad34e8a/?realtime=1 HTTP/1.0
LE_PID=$!


sleep 1
echo 'First message' >> example.log
echo 'Second message' >> example.log
sleep 1

#e First message
#e Second message

#e
#e Shutting down

