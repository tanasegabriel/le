#!/bin/bash

#############################################
#
#	Logentries Agent Installer
#
#	Supported Distro's:
#		Debian 5 and newer
#		Ubuntu 9.10 and newer
#		Fedora 14 and newer
#		CentOS 5/6  (RedHat 6)
#		Amazon AMI
#
#############################################

VERSION="1.0.7"

# Need root to run this script
if [ "$(id -u)" != "0" ]
then
	echo "Please run this install script as root."
	echo "Usage: sudo bash logentries_install.sh"
	exit 1
fi

KEY_CMD_MIT="gpg --homedir /root/.gnupg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD"
KEY_CMD_UBUNTU="gpg --homedir /root/.gnupg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys A5270289C43C79AD"
KEY_CMD_EXPORT="gpg --homedir /root/.gnupg -a --export A5270289C43C79AD"
KEY_CMD_COMPLETE="apt-key add /tmp/le.key"
KEY_CMD_CLEAN="rm /tmp/le.key"

DEBIAN_REPO_CONF="/etc/apt/sources.list.d/logentries.list"
DEBIAN_UPDATE="apt-get update"
DEBIAN_AGENT_INSTALL="apt-get install logentries -qq -y"
DEBIAN_PROCTITLE_INSTALL="apt-get install python-setproctitle -qq -y"
DEBIAN_DAEMON_INSTALL="apt-get install logentries-daemon -qq -y"
DEBIAN_CURL_INSTALL="apt-get install curl -y"

REDHAT_REPO_CONF="/etc/yum.repos.d/logentries.repo"
REDHAT_AGENT_INSTALL="yum install logentries -q -y"
REDHAT_PROCTITLE_INSTALL="yum install python-setproctitle -q -y"
REDHAT_DAEMON_INSTALL="yum install logentries-daemon -q -y"
REDHAT_CURL_INSTALL="yum install curl curl-devel -y"

GENTOO_PORTAGE="/usr/portage/local"
GENTOO_OVERLAY="app-admin/le"
GENTOO_REPO="http://rep.logentries.com/gentoo/portage/app-admin/le"
GENTOO_AGENT_INSTALL="emerge ${GENTOO_OVERLAY}"

CONFIG_DELETE_CMD="rm /etc/le/config"
REGISTER_CMD="le register"
FOLLOW_CMD="le follow"
LOGGER_CMD="logger -t LogentriesTest Test Message Sent By LogentriesAgent"
DAEMON_RESTART_CMD="if which service &>/dev/null ; then service logentries restart ; else /etc/init.d/logentries restart ; fi"
FOUND=0
AGENT_NOT_FOUND="The agent was not found after installation.\n Please contact support@logentries.com\n"
SET_ACCOUNT_KEY="--account-key="
LE_ACCOUNT_KEY=$1

TAG_NAMES=("Kernel - Process Terminated" "Kernel - Process Killed" "Kernel - Process Started" "Kernel - Process Stopped" "User Logged In" "Invalid User Login attempt" "POSSIBLE BREAK-IN ATTEMPT" "Error")
TAG_PATTERNS=("/terminated with status 100/" "/Killed process/" "/\/proc\/kmsg started/" "/Kernel logging (proc) stopped/" "/Accepted publickey for/" "/Invalid user/" "/POSSIBLE BREAK-IN ATTEMPT/" "/Invalid user admin/")
EVENT_COLOR=("66ff00" "6699ff" "009900" "ff6633" "ff0066" "9999ff" "000099" "999966")

CURL="curl"
CONTENT_HEADER="\"Content-Type: application/json\""
HEADER="-H"
DATA="--data"
API="api.logentries.com"

WGET="wget --quiet -r -np -nd"

declare -a LOGS_TO_FOLLOW=(
/var/log/syslog
/var/log/auth.log
/var/log/messages
/var/log/secure
/var/log/dmesg
/var/log/boot.log
/var/log/daemon.log
/var/log/dpkg.log
/var/log/kern.log
/var/log/lastlog
/var/log/mail.log
/var/log/user.log
/var/log/Xorg.x.log
/var/log/alternatives.log
/var/log/btmp
/var/log/cups
/var/log/anaconda.log
/var/log/cron
/var/log/wtmp
/var/log/faillog);

# Test regex pattern against LE_ACCOUNT_KEY arg 1.
regex_acct_key="[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}$"
if [ -n "$1" ] ; then
	if [[ $1 =~ $regex_acct_key ]] ; then
		printf "proceeding..."
	else
		printf "\nWrong format entered for account key.\nCorrect format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx ... Exiting installer\n\n"
		exit 1
	fi
fi

SYSLOG=messages
LOGFILE=/tmp/logentries_debug

if [ -f /etc/le/config ]; then
	printf "\n***** WARNING *****\n"
	printf "It looks like you already have the Logentries agent registered on this machine\n"
	read -p "Are you sure you want to clear your existing settings and continue with the installation? (y) or (n): "
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		$CONFIG_DELETE_CMD
		printf "OK\n"
	else
		echo ""
		printf "Exiting install script\n"
		exit 0
	fi
fi

printf "\n"

# Check if curl is installed, if not, mark it for installation
if hash curl 2>/dev/null;then
	INSTALL_CURL=0
else
	INSTALL_CURL=1
fi

printf "***** Step 1 of 3 - Beginning Logentries Installation *****\n"

if [ -f /etc/issue ] && grep "Amazon Linux AMI" /etc/issue -q; then
	# Amazon Linux AMI
cat << EOL >> $REDHAT_REPO_CONF
[logentries]
name=Logentries repo
enabled=1
metadata_expire=1d
baseurl=http://rep.logentries.com/rh/\$basearch
gpgkey=http://rep.logentries.com/RPM-GPG-KEY-logentries
EOL

	printf "Installing logentries package...\n"
	$REDHAT_AGENT_INSTALL >$LOGFILE 2>&1

	# try and install python-setproctitle
	$REDHAT_PROCTITLE_INSTALL >$LOGFILE 2>&1

	# Check for agent executable
	if [ ! -f /usr/bin/le ];then
		echo $AGENT_NOT_FOUND
		exit 1
	fi

	# Check if curl is marked for install
	if [ $INSTALL_CURL == "1" ]; then
		$REDHAT_CURL_INSTALL
	fi


	echo ""
	printf "***** Step 2 of 3 - Login *****\n"

	# Prompt the user for their Logentries credentials and register the agent
	if [[ -z "$LE_ACCOUNT_KEY" ]];then
		$REGISTER_CMD
	else
		printf "Account Key found, registering automatically...\n"
		$REGISTER_CMD $SET_ACCOUNT_KEY$LE_ACCOUNT_KEY
	fi


	printf "Installing logentries daemon package...\n"
	$REDHAT_DAEMON_INSTALL >$LOGFILE 2>&1

	FOUND=1

elif [ -f /etc/debian_version ]; then

	if hash lsb_release 2>/dev/null; then
		CODENAME=$(lsb_release -c | sed 's/Codename://' | tr -d '[:space:]')
	else
		release=$(cat /etc/debian_version)
		IFS='.' read -a array <<< "$release"

		case "${array[0]}" in
		# Debian
		7) CODENAME="wheezy"
		   ;;
		6) CODENAME="squeeze"
		   ;;
		5) CODENAME="lenny"
		   ;;
		*) CODENAME="UNKNOWN"
		   ;;
		esac
	fi

	if [ "$CODENAME" == "UNKNOWN" ]; then
		printf "Unknown distribution, please contact support@logentries.com\n"
		exit 1
	fi

	# Debian/Ubuntu
	echo "deb http://rep.logentries.com/ ${CODENAME} main" > $DEBIAN_REPO_CONF

	$KEY_CMD_MIT >$LOGFILE 2>&1

	if [ "$?" != "0" ]; then
		echo "MIT keyserver not working, fall back to ubuntu keyserver" >>$LOGFILE
		# Try different keyserver
		$KEY_CMD_UBUNTU >$LOGFILE 2>&1
	fi

	$KEY_CMD_EXPORT >/tmp/le.key
	$KEY_CMD_COMPLETE >$LOGFILE 2>&1
	$KEY_CMD_CLEAN

	printf "Updating packages...(This may take a few minutes if you have a lot of updates)\n"
	$DEBIAN_UPDATE >$LOGFILE 2>&1

	printf "Installing logentries package...\n"
	$DEBIAN_AGENT_INSTALL >$LOGFILE 2>&1
	# Try and install the python-setproctitle package on certain distro's
	$DEBIAN_PROCTITLE_INSTALL >$LOGFILE 2>&1

	# Check if agent executable exists before trying to register
	if [ ! -f /usr/bin/le ];then
		echo $AGENT_NOT_FOUND
		exit 1
	fi

	# Check if curl is marked for install
	if [ $INSTALL_CURL == "1" ]; then
		$DEBIAN_CURL_INSTALL
	fi

	printf "\n\n"
	printf "***** Step 2 of 3 - Login *****\n"

	# Prompt the user for their Logentries credentials and register the agent
	if [[ -z "$LE_ACCOUNT_KEY" ]];then
		$REGISTER_CMD
	else
		printf "Account Key found, registering automatically...\n"
		$REGISTER_CMD $SET_ACCOUNT_KEY$LE_ACCOUNT_KEY
	fi

	printf "Installing logentries daemon package...\n"
	$DEBIAN_DAEMON_INSTALL >$LOGFILE 2>&1

	FOUND=1
	SYSLOG=syslog

elif [ -f /etc/redhat-release ]; then
	# CentOS 6  /  RHEL 6 / Fedora / Amazon Linux AMI
DIST=centos5
GPG="gpgcheck=0"

if [ -f /etc/centos-release ] || [ -f /etc/fedora-release ]; then
	# Not CentOS 5, use redhat baseurl and gpgcheck
	DIST=rh
	GPG="gpgkey=http://rep.logentries.com/RPM-GPG-KEY-logentries"
fi

cat << EOL >> $REDHAT_REPO_CONF
[logentries]
name=Logentries repo
enabled=1
metadata_expire=1d
baseurl=http://rep.logentries.com/$DIST/\$basearch
$GPG
EOL

	printf "Installing logentries package...\n"
	$REDHAT_AGENT_INSTALL >$LOGFILE 2>&1

	# try and install python-setproctitle
	$REDHAT_PROCTITLE_INSTALL >$LOGFILE 2>&1

	# Check that agent executable exists before trying to register
	if [ ! -f /usr/bin/le ];then
		echo $AGENT_NOT_FOUND
	fi

	echo "\n"
	printf "***** Step 2 of 3 - Login *****\n"

	# Prompt the user for their Logentries credentials and register the agent
	if [[ -z "$LE_ACCOUNT_KEY" ]];then
		$REGISTER_CMD
	else
		printf "Account Key found, registering automatically...\n"
		$REGISTER_CMD $SET_ACCOUNT_KEY$LE_ACCOUNT_KEY
	fi

	printf "Installing logentries daemon package...\n"
	$REDHAT_DAEMON_INSTALL >$LOGFILE 2>&1

	FOUND=1

elif [ -f /etc/gentoo-release ] ; then

	if [ -d ${GENTOO_PORTAGE} ] ; then
		rm -fr ${GENTOO_PORTAGE}
	fi
	mkdir -p ${GENTOO_PORTAGE}/profiles ${GENTOO_PORTAGE}/${GENTOO_OVERLAY}

	echo 'le' > ${GENTOO_PORTAGE}/profiles/repo_name
	$WGET -A "*.ebuild","Manifest","logentries" -P ${GENTOO_PORTAGE}/${GENTOO_OVERLAY} ${GENTOO_REPO}

	for makeconf in /etc/portage/make.conf /etc/make.conf ; do
		if [ -f $makeconf ] && [ -z "`grep \"${GENTOO_PORTAGE}\" $makeconf`" ] ; then
			echo "PORTDIR_OVERLAY=\"\${PORTDIR_OVERLAY} ${GENTOO_PORTAGE}\"" >> $makeconf
			break
		fi
	done

	printf "Installing logentries package...\n"
	$GENTOO_AGENT_INSTALL &> $LOGFILE

	# Check that agent executable exists before trying to register
	if [ ! -f /usr/bin/le ] ; then
		echo $AGENT_NOT_FOUND
	fi

	echo "\n"
	printf "***** Step 2 of 3 - Login *****\n"

	# Prompt the user for their Logentries credentials and register the agent
	if [[ -z "$LE_ACCOUNT_KEY" ]];then
		$REGISTER_CMD
	else
		printf "Account Key found, registering automatically...\n"
		$REGISTER_CMD $SET_ACCOUNT_KEY$LE_ACCOUNT_KEY
	fi

	FOUND=1
fi

if [ $FOUND == "1" ]; then
	printf "Logentries Install Complete\n\n"

	logfile=/var/log/${SYSLOG}

	if [ -f $logfile ]; then
		$FOLLOW_CMD $logfile >$LOGFILE 2>&1
		printf "The Logentries agent is now monitoring $logfile\n"
	fi

	printf "\n\n"

	printf "***** Step 3 of 3 - Adding Logs to follow *****\n"

	FILES_FOUND=0

	for x in "${LOGS_TO_FOLLOW[@]}"
	do
		if [ -f $x ]; then
			let FILES_FOUND=FILES_FOUND+1
		fi
	done

	printf "$FILES_FOUND additional logs found.\n"
	read -p "Would you like to monitor all of these too? (n) allows you to choose individual logs...(y) or (n): "
	printf "\n\n"
	if [[ $REPLY =~ ^[Yy]$ ]];then
		printf "Monitoring all logs\n"
		for j in "${LOGS_TO_FOLLOW[@]}"
		do
			$FOLLOW_CMD $j >$LOGFILE 2>&1
			printf "."
		done
		printf "\n"
	else
		for j in "${LOGS_TO_FOLLOW[@]}"
		do
			if [ -f $j ]; then
				read -p "Would you like to monitor $j ?..(y) or (n): "
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					$FOLLOW_CMD $j >$LOGFILE 2>&1
				fi
			fi
		done
	fi
	eval $DAEMON_RESTART_CMD >$LOGFILE 2>&1
	printf "\n\n"
	printf "***** Install Complete! *****\n"

else
	printf "Unknown distribution. Please contact support@logentries.com with your system details\n\n"
fi
