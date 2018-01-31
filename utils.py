import os
import errno
from scapy.all import *
import traceback
import time
import sys
import logging

import socket
from socket import SHUT_WR

def close_socket( socket ):
	if ( socket != None ):
		try:
			#socket.shutdown( SHUT_WR ) # send a FIN to endpoint peer and remains for receiving additional data but BLOCK sending more data to endpoint peer
			#time.sleep(0.1) # sleep before closing the socket, so it can send eventual acks to additional data from peer
			socket.close()
		except socket.error:
			logging.error ( "[!] Error on closing socket {}".format( socket ), exc_info=True )
	
def ip_to_mac ( IP, interface ):
	try:
		logging.info ( "[*] Finding mac for IP address {}".format(IP) )
		arp_rq = ARP()
		arp_op = 1 # honest arp request
		arp_rq.hwdst = "ff:ff:ff:ff:ff:ff"
		arp_rq.pdst = IP

		ans, unans = sr ( arp_rq, retry=4, timeout=2, iface = interface, verbose=0 )
		#print (ans)
		#print (unans)

		# check if IP does not exist
		for snd,rcv in ans:
			mac = rcv[ARP].underlayer.src
			logging.info ( "Found {}".format(mac) )
			return mac

		print ( "[!] It seems IP address is unreachable. No mac found. Exiting.." )
		sys.exit()

	except OSError as ose:
		if ( ose.errno == 19 ):
			logging.error ("[!] The interface {} does not exist!".format(interface))
			#print ( traceback.format_exc() )
			return
		else:
			logging.error ("[!] {} is not a valid IP address!".format(IP) )
			#print ( traceback.format_exc() )
			return
	except socket.error:
		logging.error ( exc_info=True )
		return

def iptables_clean ():
	os.system ( "iptables -t nat -F" )

def iptables_accept ( configs ):
	# add an iptables rule to accept incoming packets destined to another node
	#print (configs['mitm']['ip'])
	command = "iptables -t nat -A PREROUTING -d "+configs['server']['ip']+" -j DNAT --to "+configs['mitm']['ip']
	#print (command)
	#os.system ( "iptables -t nat -A PREROUTING -d %configs['target']['ip']% -j DNAT --to %configs['mitm']['ip']%" ) # port will be the one specified in the incoming packet
	os.system ( command )

