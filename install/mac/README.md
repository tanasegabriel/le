Agent installer for OS X
========================

Installation
------------

To install, download `install.sh` and run:

```shell
$ curl -O https://raw.githubusercontent.com/logentries/le/master/install/mac/install.sh
$ chmod +x install.sh
$ sudo ./install.sh
```

Alternatively you can install the Agent with brew.
```shell
brew install logentries
```

Removal
-------

Stop and remove the daemon:

```shell
$ sudo launchctl unload /Library/LaunchDaemons/com.logentries.agent.plist
$ sudo rm /Library/LaunchDaemons/com.logentries.agent.plist
```

Then remove the executable:

```shell
$ sudo rm /usr/bin/le
```

If you installed the Agent via brew you need to run the following.
```shell
brew uninstall logentries
```