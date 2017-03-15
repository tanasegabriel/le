Logentries Agent Tests
======================

This directory contains a simple testing framework together with a set of tests. It provides a partially virutalized environment for speed and simplicity.

All features must be covered.

Tests are located in `tests.d` directory. Specific features are split into separate files. If there are too many test cases per single file, it's advisable to split them into more fine-grained scenarios.

Tests requires some Python packages which are not included in standard installations. Best option is to run tests in a separate environment created by `virtualenv`. You may need to install packages from `requirements.apt` files. Then run the following commands to create and activate one:

	virtualenv env
	source env/bin/activate
	pip install -r requirements.pip

Now you should be good to run all tests.


Running tests
-------------

Run all tests by executing `tests.sh` script:

	./tests.sh

Or run selected test only by specifying file name:

	./tests.sh tests.d/formatters.sh

Or, if you are interested in full output, run the test directly:

	tests.d/formatters.sh

The `testd.sh` script extracts expected output and compares it against actual output. The difference is then displayed; unless they are the same in which case `SUCCESS` is displayed.


Writing tests
-------------

Tests are bash scripts located in `tests.d`. Supporting variables and functions are inherited from `vars` file. Simply put this line on top to inherit them and run mock API server:

	. vars

Typically test starts defining a scenario:

	Scenario 'Default formatters use'

Then a set of test cases:

	Testcase 'Default formatter for HTTP PUT is plain'

Each scenario clears configuration files, but leaves other files untouched. Test cases do not modify the environment.

Expected output is specified as a bash comment `#` followed by `e` for standard error or `o` for standard output. ISO dates must be replaced with `ISODATETIME` keyword. Since home directory is generated, replace any occurrence with `$TMP`.

Common (useful) variables and functions:

* Scenario 'xxx' - declares a new scenario, clears configuration files
* Testcase 'xxx' - declares a new test case
* $LE le agent executable with debugging enabled
* $TMP home directory of the test
* $ACCOUNT_KEY tested account key, used for convenience by mock server
* $HOST_KEY tested host key, used for convenience by mock server

API and data server mocks
-------------------------

Mock of API and data servers are located in `mocks` directory. They are executed automatically from `vars`.


Running tests with docker
--------------------------

If you are not using Debian, you should use the provided Docker container to run the tests.

The docker container is configured with everything you need to run the tests. You can build the container
from the project root directory with the following command:

    docker build -t le_agent .
    
This will build a docker image called le_agent. The first time you run this command, 
it may take 10-15 minutes to build the container. Subsequent runs should be significantly faster.
    
Once the container is built, you can run it with the following command:

    docker run -it le_agent
    
There is a convenience script that will run the tests & execute pylint. It can be run with:

    ./run_tests.sh
    
You can run the tests manually with the following command:

    cd /le/test && virtualenv env && source env/bin/activate && pip install -r requirements.pip && ./tests.sh
    
Pylint can also be run manually on the docker container with:

    cd /le && pylint src
