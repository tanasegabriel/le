#!/bin/bash

. vars


Scenario 'Unicode handling'

Testcase 'The agent accepts lines encoded in Unicode'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
echo 'api-key = 459c6737-375a-447b-aa2a-56cd1400a34c' >>"$CONFIG"
#e Initialized

touch example.log
$LE --debug-transport-events monitor &
#e Configuration files loaded: sandbox_config
#e Connecting to 127.0.0.1:8081
#e Domain request: GET /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/ None {}
#e List response: {"object": "loglist", "list": [{"name": "Log name 0", "key": "400da462-36fa-48f4-bb4e-87f96ad34e8a", "created": 1414611930412, "retention": -1, "follow": "true", "object": "log", "type": "agent", "filename": "$TMP/example.log"}, {"logtype": "444e607f-14bd-405e-a2ce-c4892b5a3b15", "token": "120fb800-94c0-446a-be28-cfbbc36b52eb", "name": "Log name 1", "key": "ee0489cc-41ce-41cf-9bb6-4cdf5e5acf32", "created": 1418775058756, "retention": -1, "follow": "false", "object": "log", "type": "token", "filename": "$TMP/example2.log"}], "response": "ok"}
#e Following $TMP/example.log
#e Opening connection 127.0.0.1:8081 PUT /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/400da462-36fa-48f4-bb4e-87f96ad34e8a/?realtime=1 HTTP/1.0
LE_PID=$!

sleep 1
echo 'Message: ěščřžýáíéů' >> example.log
#e Message: ěščřžýáíéů
sleep 1

#e
#e Shutting down

