#!/usr/bin/env python2

#
# Logentries data server mock
#

from twisted.internet import protocol, reactor, endpoints

class Listen( protocol.Protocol):
	def dataReceived(self, data):
		pass

class ListenFactory( protocol.Factory):
	def buildProtocol(self, addr):
		return Listen()

if __name__ == "__main__":
	endpoints.serverFromString(reactor, "tcp:10000").listen(ListenFactory())
	reactor.run()

