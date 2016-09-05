#!/bin/bash

. vars

Scenario 'Direct format specification'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

tee >>"$CONFIG" <<EOF
pull-server-side-config = False
[apache]
token = 3fc10892-51e3-4865-b35d-eac9de6e3e52
path = $TMP/example.log
formatter = abraka \$isodatetime dabra \$hostname \$appname \$line
EOF


touch example.log
$LE --debug-transport-events monitor &
#e Configuration files loaded: sandbox_config
#e Following $TMP/example.log
#e Opening connection 127.0.0.1:10000 
LE_PID=$!

sleep 1
echo 'First message' >> example.log
#e 3fc10892-51e3-4865-b35d-eac9de6e3e52abraka ISODATETIME dabra myhost apache First message
echo 'Second message' >> example.log
#e 3fc10892-51e3-4865-b35d-eac9de6e3e52abraka ISODATETIME dabra myhost apache Second message
sleep 1

kill $LE_PID
wait $LE_PID 2>/dev/null || true

