#!/usr/bin/env bash

#Run Pylint
cd /le
pylint src

#Run tests
cd /le/test
virtualenv env
source env/bin/activate
pip install -r /le/test/requirements.pip
./tests.sh

