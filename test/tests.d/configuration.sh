#!/bin/bash

. vars

Scenario 'Configuration with basic options'

Testcase 'Basic configuration'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY
#e Initialized

cat $CONFIG | grep user-key
#o user-key = f720fe54-879a-11e4-81ac-277d856f873e
cat $CONFIG | grep agent-key
#o agent-key = 41ae887a-284a-4d78-91fe-56485b076148
cat $CONFIG | grep metrics-net
#o metrics-net = sum
cat $CONFIG | grep metrics-mem
#o metrics-mem = system
cat $CONFIG | grep metrics-space
#o metrics-space = /
cat $CONFIG | grep metrics-token
#o metrics-token = 
cat $CONFIG | grep metrics-interval
#o metrics-interval = 5s
cat $CONFIG | grep metrics-swap
#o metrics-swap = system
cat $CONFIG | grep metrics-cpu
#o metrics-cpu = system
cat $CONFIG | grep metrics-vcpu
#o metrics-vcpu = 
cat $CONFIG | grep metrics-disk
#o metrics-disk = sum


Scenario 'Configuration with other options'

$LE init --account-key=$ACCOUNT_KEY --host-key=$HOST_KEY --suppress-ssl --datahub "localhost:5000" --hostname "abarakedabra"
#e Initialized


cat $CONFIG | grep user-key
#o user-key = f720fe54-879a-11e4-81ac-277d856f873e
cat $CONFIG | grep agent-key
#o agent-key = 41ae887a-284a-4d78-91fe-56485b076148
cat $CONFIG | grep metrics-net
#o metrics-net = sum
cat $CONFIG | grep metrics-mem
#o metrics-mem = system
cat $CONFIG | grep metrics-space
#o metrics-space = /
cat $CONFIG | grep metrics-token
#o metrics-token = 
cat $CONFIG | grep metrics-interval
#o metrics-interval = 5s
cat $CONFIG | grep metrics-swap
#o metrics-swap = system
cat $CONFIG | grep metrics-cpu
#o metrics-cpu = system
cat $CONFIG | grep metrics-vcpu
#o metrics-vcpu = 
cat $CONFIG | grep metrics-disk
#o metrics-disk = sum
cat $CONFIG | grep hostname
#o hostname = abarakedabra
cat $CONFIG | grep suppress_ssl
#o suppress_ssl = True
cat $CONFIG | grep datahub
#o datahub = localhost:5000


Scenario 'Re-init with locally configured logset'

$LE init --account-key=$ACCOUNT_KEY
#e Initialized

cat $CONFIG | grep user-key
#o user-key = f720fe54-879a-11e4-81ac-277d856f873e
cat $CONFIG | grep metrics-net
#o metrics-net = sum
cat $CONFIG | grep metrics-mem
#o metrics-mem = system
cat $CONFIG | grep metrics-space
#o metrics-space = /
cat $CONFIG | grep metrics-token
#o metrics-token = 
cat $CONFIG | grep metrics-interval
#o metrics-interval = 5s
cat $CONFIG | grep metrics-swap
#o metrics-swap = system
cat $CONFIG | grep metrics-cpu
#o metrics-cpu = system
cat $CONFIG | grep metrics-vcpu
#o metrics-vcpu = 
cat $CONFIG | grep metrics-disk
#o metrics-disk = sum

echo [syslog] >> $CONFIG
echo path=/var/log/syslog >> $CONFIG
echo token=629cc7e9-3344-4cef-b364-7fb6baeb74f2 >> $CONFIG

echo [Log name 1] >> $CONFIG
echo path=/var/log/messages >> $CONFIG
echo destination=Name2/Log name 1 >> $CONFIG

$LE reinit --pull-server-side-config=False
#e Configuration files loaded: sandbox_config
#e Reinitialized

cat $CONFIG | grep user-key
#o user-key = f720fe54-879a-11e4-81ac-277d856f873e
cat $CONFIG | grep metrics-net
#o metrics-net = sum
cat $CONFIG | grep metrics-mem
#o metrics-mem = system
cat $CONFIG | grep metrics-space
#o metrics-space = /
cat $CONFIG | grep metrics-token
#o metrics-token = 
cat $CONFIG | grep metrics-interval
#o metrics-interval = 5s
cat $CONFIG | grep metrics-swap
#o metrics-swap = system
cat $CONFIG | grep metrics-cpu
#o metrics-cpu = system
cat $CONFIG | grep metrics-vcpu
#o metrics-vcpu = 
cat $CONFIG | grep metrics-disk
#o metrics-disk = sum
cat $CONFIG | grep -v metrics-token | grep token
#o token = 629cc7e9-3344-4cef-b364-7fb6baeb74f2
cat $CONFIG | grep path
#o path = /var/log/syslog
#o path = /var/log/messages
cat $CONFIG | grep destination
#o destination = Name2/Log name 1


Scenario 'Re-init with locally configured log'

$LE reinit --pull-server-side-config=False --suppress-ssl --datahub="127.0.0.1:10000" --hostname "abarakedabra"
#e Reinitialized

echo [syslog] >> $CONFIG
echo path=/var/log/syslog >> $CONFIG
echo token=629cc7e9-3344-4cef-b364-7fb6baeb74f2 >> $CONFIG

$LE reinit --pull-server-side-config=False --suppress-ssl --datahub="127.0.0.1:10000"
#e Configuration files loaded: sandbox_config
#e Reinitialized

cat $CONFIG | grep metrics-net
#o metrics-net = sum
cat $CONFIG | grep metrics-mem
#o metrics-mem = system
cat $CONFIG | grep metrics-space
#o metrics-space = /
cat $CONFIG | grep metrics-token
#o metrics-token = 
cat $CONFIG | grep metrics-interval
#o metrics-interval = 5s
cat $CONFIG | grep metrics-swap
#o metrics-swap = system
cat $CONFIG | grep metrics-cpu
#o metrics-cpu = system
cat $CONFIG | grep metrics-vcpu
#o metrics-vcpu = 
cat $CONFIG | grep metrics-disk
#o metrics-disk = sum
cat $CONFIG | grep -v metrics-token | grep token
#o token = 629cc7e9-3344-4cef-b364-7fb6baeb74f2
cat $CONFIG | grep path
#o path = /var/log/syslog
