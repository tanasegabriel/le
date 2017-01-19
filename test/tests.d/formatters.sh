#!/bin/bash

. vars

Scenario 'Default formatters use'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

Testcase 'Default formatter for HTTP PUT is plain'

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
echo 'First message' >> example.log
#e First message
echo 'Second message' >> example.log
#e Second message
sleep 1

kill $LE_PID
wait $LE_PID 2>/dev/null || true

#e
#e Shutting down


Testcase 'Default formatter for TCP input is syslog'

echo 'pull-server-side-config = False' >>"$CONFIG"
echo '[Web]' >>"$CONFIG"
echo 'token = 89caf699-8fb7-45b1-a41f-ae111ec99148' >>"$CONFIG"
echo "path = $TMP/example.log" >>"$CONFIG"
touch example.log
$LE --debug-transport-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
LE_PID=$!

sleep 1
echo 'First message' >> example.log
#e 89caf699-8fb7-45b1-a41f-ae111ec99148<14>1 ISODATETIME myhost Web - - - First message
echo 'Second message' >> example.log
#e 89caf699-8fb7-45b1-a41f-ae111ec99148<14>1 ISODATETIME myhost Web - - - Second message
sleep 1

kill $LE_PID
wait $LE_PID 2>/dev/null || true

#e
#e Shutting down

Scenario 'Global formatter settings'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

Testcase 'Setting global formatter affects HTTP PUT'

echo 'formatter = syslog' >>"$CONFIG"
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
echo 'First message' >> example.log
#e <14>1 ISODATETIME myhost Log_name_0 - - - First message
echo 'Second message' >> example.log
#e <14>1 ISODATETIME myhost Log_name_0 - - - Second message
sleep 1

kill $LE_PID
wait $LE_PID 2>/dev/null || true

#e
#e Shutting down


Testcase 'Setting global formatter affects TCP'

echo 'formatter = plain' >>"$CONFIG" # This overrides previous settings of formatter = syslog
echo 'pull-server-side-config = False' >>"$CONFIG"
echo '[Web]' >>"$CONFIG"
echo 'token = d0d3760d-970a-465c-b580-368c12981b2c' >>"$CONFIG"
echo "path = $TMP/example.log" >>"$CONFIG"
touch example.log
$LE --debug-transport-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
LE_PID=$!

sleep 1
echo 'First message' >> example.log
#e d0d3760d-970a-465c-b580-368c12981b2cFirst message
echo 'Second message' >> example.log
#e d0d3760d-970a-465c-b580-368c12981b2cSecond message
sleep 1

kill $LE_PID
wait $LE_PID 2>/dev/null || true

#e
#e Shutting down


Scenario 'Setting section formatter affects logs from that section'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

echo 'pull-server-side-config = False' >>"$CONFIG"
echo '[Web]' >>"$CONFIG"
echo 'token = 053f0e3c-f7a3-434c-91b2-446363f47a21' >>"$CONFIG"
echo "path = $TMP/example.log" >>"$CONFIG"
echo "formatter = plain" >>"$CONFIG"
touch example.log
$LE --debug-transport-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
LE_PID=$!

sleep 1
echo 'First message' >> example.log
#e 053f0e3c-f7a3-434c-91b2-446363f47a21First message
echo 'Second message' >> example.log
#e 053f0e3c-f7a3-434c-91b2-446363f47a21Second message
sleep 1

#e
#e Shutting down

