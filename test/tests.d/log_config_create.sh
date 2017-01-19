#!/bin/bash

. vars

Scenario 'Creating log from configuration'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY
#e Initialized

tee >>"$CONFIG" <<EOF
[cassandra]
path=$TMP/system.out
destination=Name2/Log name 1
EOF

Testcase 'Monitoring'

touch system.out
touch example.log
$LE --debug-events monitor &

#e Configuration files loaded: sandbox_config
#e Connecting to 127.0.0.1:8081
#e Domain request: POST / user_key=f720fe54-879a-11e4-81ac-277d856f873e&load_hosts=true&request=get_user&load_logs=true {'Content-Type': 'application/x-www-form-urlencoded'}
#e Domain response: "{"hosts": [{"distver": "wheezy", "c": 1315863111149, "hostname": "0.example.com", "name": "Name1", "distname": "Debian", "object": "host", "key": "41ae887a-284a-4d78-91fe-56485b076148", "logs": [{"name": "Log name 0", "key": "400da462-36fa-48f4-bb4e-87f96ad34e8a", "created": 1414611930412, "retention": -1, "follow": "true", "object": "log", "type": "agent", "filename": "$TMP/example.log"}]}, {"distver": "jessie", "c": 1385398282448, "hostname": "1.example.com", "name": "Name2", "distname": "Debian", "object": "host", "key": "86707421-6a05-4c70-9034-e5e30b6a1a44", "logs": [{"logtype": "444e607f-14bd-405e-a2ce-c4892b5a3b15", "token": "120fb800-94c0-446a-be28-cfbbc36b52eb", "name": "Log name 1", "key": "ee0489cc-41ce-41cf-9bb6-4cdf5e5acf32", "created": 1418775058756, "retention": -1, "follow": "false", "object": "log", "type": "token", "filename": "$TMP/example2.log"}]}], "response": "ok"}"
#e Connecting to 127.0.0.1:8081
#e Domain request: POST / user_key=f720fe54-879a-11e4-81ac-277d856f873e&load_hosts=true&request=get_user&load_logs=true {'Content-Type': 'application/x-www-form-urlencoded'}
#e Domain response: "{"hosts": [{"distver": "wheezy", "c": 1315863111149, "hostname": "0.example.com", "name": "Name1", "distname": "Debian", "object": "host", "key": "41ae887a-284a-4d78-91fe-56485b076148", "logs": [{"name": "Log name 0", "key": "400da462-36fa-48f4-bb4e-87f96ad34e8a", "created": 1414611930412, "retention": -1, "follow": "true", "object": "log", "type": "agent", "filename": "$TMP/example.log"}]}, {"distver": "jessie", "c": 1385398282448, "hostname": "1.example.com", "name": "Name2", "distname": "Debian", "object": "host", "key": "86707421-6a05-4c70-9034-e5e30b6a1a44", "logs": [{"logtype": "444e607f-14bd-405e-a2ce-c4892b5a3b15", "token": "120fb800-94c0-446a-be28-cfbbc36b52eb", "name": "Log name 1", "key": "ee0489cc-41ce-41cf-9bb6-4cdf5e5acf32", "created": 1418775058756, "retention": -1, "follow": "false", "object": "log", "type": "token", "filename": "$TMP/example2.log"}]}], "response": "ok"}"
#e Connecting to 127.0.0.1:8081
#e Domain request: GET /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/ None {}
#e List response: {"object": "loglist", "list": [{"name": "Log name 0", "key": "400da462-36fa-48f4-bb4e-87f96ad34e8a", "created": 1414611930412, "retention": -1, "follow": "true", "object": "log", "type": "agent", "filename": "$TMP/example.log"}, {"logtype": "444e607f-14bd-405e-a2ce-c4892b5a3b15", "token": "120fb800-94c0-446a-be28-cfbbc36b52eb", "name": "Log name 1", "key": "ee0489cc-41ce-41cf-9bb6-4cdf5e5acf32", "created": 1418775058756, "retention": -1, "follow": "false", "object": "log", "type": "token", "filename": "$TMP/example2.log"}], "response": "ok"}
#e Following $TMP/example.log
#e Opening connection 127.0.0.1:8081 PUT /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/400da462-36fa-48f4-bb4e-87f96ad34e8a/?realtime=1 HTTP/1.0
#e Following $TMP/system.out


LE_PID=$!

sleep 1
echo 'First message' >> system.out
echo 'Second message' >> system.out
sleep 1

#e First message
#e Second message

#e
#e Shutting down

