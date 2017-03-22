#!/bin/bash

. vars

#
# Check that we are able to save state and retrieve it back
#

Scenario 'We are able to save state and retrieve it back'

Testcase 'Init'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
echo 'api-key = 459c6737-375a-447b-aa2a-56cd1400a34c' >>"$CONFIG"

#e Initialized
echo "state-file = $TMP/state-file" >>"$CONFIG"
echo 'pull-server-side-config = False' >>"$CONFIG"
echo '[Web]' >>"$CONFIG"
echo 'token = 0b52788c-7981-4138-ac40-6720ae2d5f0c' >>"$CONFIG"
echo "path = $TMP/example.log" >>"$CONFIG"

Testcase 'Monitoring - first phrase'

touch example.log
echo 'Message 1 (skipped)' >> example.log
$LE --debug-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
LE_PID=$!

sleep 2
echo 'Message 2' >> example.log
echo 'Message 3' >> example.log
sync
sleep 2

#e
#e Message 2
#e Message 3

kill $LE_PID
wait $LE_PID

#e Shutting down

Testcase 'Monitoring - second phrase'

echo 'Message 4 (not to be lost)' >> example.log
echo 'Message 5 (not to be lost)' >> example.log
sync

$LE --debug-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
LE_PID=$!

#e
#e Message 4 (not to be lost)
#e Message 5 (not to be lost)

sleep 2

#e Shutting down

