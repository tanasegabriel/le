#!/bin/bash

. vars

Scenario 'User supplied formatter code'

mkdir Formatters
touch Formatters/__init__.py
tee >Formatters/formatters.py <<EOF

class Form(object):
	def __init__(self, identity, hostname, log_name, token):
		self.identity = identity
		self.hostname = hostname
		self.log_name = log_name
		self.token = token

	def format_line(self, line):
		return '%s %s %s %s %s'%(self.identity, self.hostname, self.log_name, self.token, line)

formatters = {
	'apache' : lambda hostname, log_name, token: Form('log_name', hostname, log_name, token).format_line,
	'f73bb3bd-8c6e-4299-807d-985756947419' : lambda hostname, log_name, token: Form('token', hostname, log_name, token).format_line,
	'400da462-36fa-48f4-bb4e-87f96ad34e8a' : lambda hostname, log_name, token: Form('log_id', hostname, log_name, token).format_line,
}
EOF


Testcase 'Matching formatter based on name'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

tee >>"$CONFIG" <<EOF
api-key = 459c6737-375a-447b-aa2a-56cd1400a34c
pull-server-side-config = False
formatters = Formatters
[apache]
token = d86382bb-2a80-408a-8f3a-c684467e6082
path = $TMP/example.log
EOF

touch example.log
$LE --debug-transport-events monitor --debug-formatters &
#e Configuration files loaded: sandbox_config
#e Available formatters: ['apache', '400da462-36fa-48f4-bb4e-87f96ad34e8a', 'f73bb3bd-8c6e-4299-807d-985756947419']
#e  Looking for formatters by log_name=apache id= token=d86382bb-2a80-408a-8f3a-c684467e6082
#e  Looking for formatters by log name
#e  Formatter found
#e Following $TMP/example.log
LE_PID=$!

sleep 1
echo 'First message' >> example.log
#e log_name myhost apache d86382bb-2a80-408a-8f3a-c684467e6082 First message
echo 'Second message' >> example.log
#e log_name myhost apache d86382bb-2a80-408a-8f3a-c684467e6082 Second message
sleep 1

kill $LE_PID
wait $LE_PID 2>/dev/null || true

#e
#e Shutting down


Testcase 'Matching formatter based on log token'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

tee >>"$CONFIG" <<EOF
api-key = 459c6737-375a-447b-aa2a-56cd1400a34c
pull-server-side-config = False
formatters = Formatters
[cassandra]
token = f73bb3bd-8c6e-4299-807d-985756947419
path = $TMP/example.log
EOF

touch example.log
$LE --debug-transport-events monitor --debug-formatters &
#e Configuration files loaded: sandbox_config
#e Available formatters: ['apache', '400da462-36fa-48f4-bb4e-87f96ad34e8a', 'f73bb3bd-8c6e-4299-807d-985756947419']
#e  Looking for formatters by log_name=cassandra id= token=f73bb3bd-8c6e-4299-807d-985756947419
#e  Looking for formatters by log name
#e  No formatter found by log name
#e  Looking for formatters by token
#e  Formatter found
#e Following $TMP/example.log
LE_PID=$!

sleep 1
echo 'First message' >> example.log
#e token myhost cassandra f73bb3bd-8c6e-4299-807d-985756947419 First message
echo 'Second message' >> example.log
#e token myhost cassandra f73bb3bd-8c6e-4299-807d-985756947419 Second message
sleep 1

kill $LE_PID
wait $LE_PID 2>/dev/null || true

#e
#e Shutting down



Testcase 'Matching formatter based on log ID'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --hostname myhost
#e Initialized

tee >>"$CONFIG" <<EOF
api-key = 459c6737-375a-447b-aa2a-56cd1400a34c
formatters = Formatters
EOF

touch example.log
$LE --debug-transport-events monitor --debug-formatters &
#e Configuration files loaded: sandbox_config
#e Connecting to 127.0.0.1:8081
#e Domain request: GET /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/ None {}
#e List response: {"object": "loglist", "list": [{"name": "Log name 0", "key": "400da462-36fa-48f4-bb4e-87f96ad34e8a", "created": 1414611930412, "retention": -1, "follow": "true", "object": "log", "type": "agent", "filename": "$TMP/example.log"}, {"logtype": "444e607f-14bd-405e-a2ce-c4892b5a3b15", "token": "120fb800-94c0-446a-be28-cfbbc36b52eb", "name": "Log name 1", "key": "ee0489cc-41ce-41cf-9bb6-4cdf5e5acf32", "created": 1418775058756, "retention": -1, "follow": "false", "object": "log", "type": "token", "filename": "$TMP/example2.log"}], "response": "ok"}
#e Available formatters: ['apache', '400da462-36fa-48f4-bb4e-87f96ad34e8a', 'f73bb3bd-8c6e-4299-807d-985756947419']
#e  Looking for formatters by log_name=Log name 0 id=400da462-36fa-48f4-bb4e-87f96ad34e8a token=
#e  Looking for formatters by log name
#e  No formatter found by log name
#e  Looking for formatters by log ID
#e  Formatter found
#e Following $TMP/example.log
#e Opening connection 127.0.0.1:8081 PUT /f720fe54-879a-11e4-81ac-277d856f873e/hosts/41ae887a-284a-4d78-91fe-56485b076148/400da462-36fa-48f4-bb4e-87f96ad34e8a/?realtime=1 HTTP/1.0
LE_PID=$!

sleep 1
echo 'First message' >> example.log
#e log_id myhost Log name 0  First message
echo 'Second message' >> example.log
#e log_id myhost Log name 0  Second message
sleep 1

#e
#e Shutting down

