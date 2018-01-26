import os
import errno
from scapy.all import *
import traceback
import time

def ip_to_mac ( IP, interface ):
	try:
		arp_rq = ARP()
		arp_op = 1 # honest arp request
		arp_rq.hwdst = "ff:ff:ff:ff:ff:ff"
		arp_rq.pdst = IP

		ans, unans = sr ( arp_rq, retry=10, timeout=2, iface = interface, verbose=0 )
		#print (ans)
		#print (unans)

		# check if IP does not exist
		for snd,rcv in ans:
			return rcv[ARP].underlayer.src

		return None
	except OSError as ose:
		if ( ose.errno == 19 ):
			print("[!] The interface %s does not exist!" % interface)
			#print ( traceback.format_exc() )
			return
		else:
			print ("[!] %s is not a valid IP address!" % IP )
			#print ( traceback.format_exc() )
			return
	except socket.error:
		print ( traceback.format_exc() )
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
