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
#o [Main]
#o user-key = f720fe54-879a-11e4-81ac-277d856f873e
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
#e Configuration files loaded: sandbox_config
#e Connecting to 127.0.0.1:8081
#e Domain request: POST / distver=%DEBIAN_VERSION_ENC%&name=Name&distname=Debian&hostname=Hostname&request=register&system=Linux&user_key=f720fe54-879a-11e4-81ac-277d856f873e {'Content-Type': 'application/x-www-form-urlencoded'}
#e Domain response: "{"host": {"distver": "%DEBIAN_VERSION%", "c": 1315863111149, "hostname": "Hostname", "name": "Name", "distname": "Debian", "object": "host", "key": "41ae887a-284a-4d78-91fe-56485b076148"}, "agent_key": "41ae887a-284a-4d78-91fe-56485b076148", "host_key": "41ae887a-284a-4d78-91fe-56485b076148", "worker": "a0", "response": "ok"}"
#e Registered Name (Hostname)

Testcase 'Follow'

touch example.log example2.log
$LE follow example.log
#e Configuration files loaded: sandbox_config
#e Connecting to 127.0.0.1:8081
#e Domain request: GET /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/ None {}
#e List response: {"object": "loglist", "list": [{"name": "Log name 0", "key": "400da462-36fa-48f4-bb4e-87f96ad34e8a", "created": 1414611930412, "retention": -1, "follow": "true", "object": "log", "type": "agent", "filename": "$TMP/example.log"}, {"logtype": "444e607f-14bd-405e-a2ce-c4892b5a3b15", "token": "120fb800-94c0-446a-be28-cfbbc36b52eb", "name": "Log name 1", "key": "ee0489cc-41ce-41cf-9bb6-4cdf5e5acf32", "created": 1418775058756, "retention": -1, "follow": "false", "object": "log", "type": "token", "filename": "$TMP/example2.log"}], "response": "ok"}
#e Already following $TMP/example.log


echo 'Skip this message' >> example.log

Testcase 'Monitoring'

$LE --debug-events monitor &
#e Configuration files loaded: sandbox_config
#e Connecting to 127.0.0.1:8081
#e Domain request: GET /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/ None {}
#e List response: {"object": "loglist", "list": [{"name": "Log name 0", "key": "400da462-36fa-48f4-bb4e-87f96ad34e8a", "created": 1414611930412, "retention": -1, "follow": "true", "object": "log", "type": "agent", "filename": "$TMP/example.log"}, {"logtype": "444e607f-14bd-405e-a2ce-c4892b5a3b15", "token": "120fb800-94c0-446a-be28-cfbbc36b52eb", "name": "Log name 1", "key": "ee0489cc-41ce-41cf-9bb6-4cdf5e5acf32", "created": 1418775058756, "retention": -1, "follow": "false", "object": "log", "type": "token", "filename": "$TMP/example2.log"}], "response": "ok"}
#e Following $TMP/example.log
#e Opening connection 127.0.0.1:8081 PUT /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/400da462-36fa-48f4-bb4e-87f96ad34e8a/?realtime=1 HTTP/1.0
LE_PID=$!


sleep 1
echo 'First message' >> example.log
echo 'Second message' >> example.log
sleep 1

#e First message
#e Second message

