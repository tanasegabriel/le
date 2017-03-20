#!/usr/bin/env bash

#Run Pylint
cd /le
pylint src

#Run tests
cd /le/test
virtualenv env
source env/bin/activate
pip install -r /le/test/requirements.pip
cd /le
python setup.py build
python setup.py install
cd /le/test
./tests.sh

