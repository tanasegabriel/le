Common packaging and distribution
---------------------------------


Stand-alone
-----------

Just works as a standa-alone application. Preferably install Python 2.7 with SSL support.


Debian 7.0 Wheezy
------------------

	su -
	echo 'deb http://rep.logentries.com/ wheezy main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	aptitude update
	aptitude install logentries
	exit


Debian 8.0 Jessie/SID
---------------------

	su -
	echo 'deb http://rep.logentries.com/ jessie main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	aptitude update
	aptitude install logentries
	exit


Ubuntu 11.10 Oneiric Ocelot
-----------------------------

	sudo -sH
	echo 'deb http://rep.logentries.com/ oneiric main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	apt-get update
	apt-get install logentries
	exit


Ubuntu 13.04 Raring Ringtail
-----------------------------

	sudo -sH
	echo 'deb http://rep.logentries.com/ raring main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	apt-get update
	apt-get install logentries
	exit


Ubuntu 13.10 Saucy Salamander
-----------------------------

	sudo -sH
	echo 'deb http://rep.logentries.com/ saucy main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	aptitude update
	aptitude install logentries
	exit


Ubuntu 14.04 Trusty Tahr
------------------------

	sudo -sH
	echo 'deb http://rep.logentries.com/ trusty main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	apt-get update
	apt-get install logentries
	exit


Ubuntu 15.04 Vivid Vervet
-------------------------

	sudo -sH
	echo 'deb http://rep.logentries.com/ vivid main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	apt-get update
	apt-get install logentries
	exit


Ubuntu 15.10 Wily Werewolf
--------------------------

	sudo -sH
	echo 'deb http://rep.logentries.com/ wily main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	apt-get update
	apt-get install logentries
	exit


Ubuntu 16.04 Xenial Xerus
-------------------------

	sudo -sH
	echo 'deb http://rep.logentries.com/ xenial main' >/etc/apt/sources.list.d/logentries.list
	gpg --keyserver hkp://pgp.mit.edu:80 --recv-keys A5270289C43C79AD && gpg -a --export A5270289C43C79AD | apt-key add -
	apt-get update
	apt-get install logentries
	exit

Debian and Ubuntu enforce SHA256 digest in the Release and/or Packages files. Expect a warning message.


Fedora 14-19
------------

	su -
	tee /etc/yum.repos.d/logentries.repo <<EOF
	[logentries]
	name=Logentries repo
	enabled=1
	metadata_expire=1d
	baseurl=http://rep.logentries.com/fedora\$releasever/\$basearch
	gpgkey=http://rep.logentries.com/RPM-GPG-KEY-logentries
	EOF
	yum update
	yum install logentries
	exit


Fedora 20
---------

	su -
	yum-config-manager --add-repo http://rep.logentries.com/helpers/fedora20/logentries.repo
	yum update
	yum install logentries
	exit


Amazon Linux AMI
-------------

	su -
	tee /etc/yum.repos.d/logentries.repo <<EOF
	[logentries]
	name=Logentries repo
	enabled=1
	metadata_expire=1d
	baseurl=http://rep.logentries.com/amazonlatest/\$basearch
	gpgkey=http://rep.logentries.com/RPM-GPG-KEY-logentries
	EOF
	yum update
	yum install logentries
	exit


CentOS 5, 6
-----------

	su -
	tee /etc/yum.repos.d/logentries.repo <<EOF
	[logentries]
	name=Logentries repo
	enabled=1
	metadata_expire=1d
	gpgcheck=0
	baseurl=http://rep.logentries.com/centos\$releasever/\$basearch
	EOF
	yum update
	yum install logentries
	exit


CentOS 7
--------

	su -
	rpm --import https://rep.logentries.com/RPM-GPG-KEY-logentries
	tee /etc/yum.repos.d/logentries.repo <<EOF
	[logentries]
	name=Logentries repo
	enabled=1
	metadata_expire=1d
	gpgcheck=1
	baseurl=http://rep.logentries.com/centos\$releasever/\$basearch
	EOF
	yum update
	yum install logentries
	exit


FreeBSD 10.2
------------

Install support for SSL:

	cd /usr/ports/security/ca_root_nss
	make install

Install Python:

	cs /usr/ports/lang/python27
	make install

