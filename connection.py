import socket
import ssl
import traceback
import errno
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR, IPPROTO_IP
import time
import threading
import logging

from parser.http import *
#4096
BUF_SIZE = 8192
TIMEOUT = 0.2
RETRY = 4
DEBUG = 1

def print_debug ( string ):
	
	if (DEBUG == 0) : 
		
		logging.debug ( string )
	else: 
		return

# fts will wait data from client and forward to server
def forward_to_server ( client, server, clock, slock, client_stop, server_stop ):
	retry=0
	roundd = 1
	while (not server_stop.is_set()):
		print_debug ( "[1] Forward To Server thread BEGIN\t[round {}] [retry {}]".format(roundd, retry) )
		try:
			clock.acquire()
			print_debug ("  [1] fts acquired clock! Now is waiting for data from client...")
			print_debug ("  [1] Recv...")
			data = client.recv ( BUF_SIZE )
			#print_debug( "  [1] Received from client:\n", data.decode() )
			clock.release()
			print_debug ("  [1][R] fts released clock! It received some data from client, it could be empty: {}".format(len(data)) )

			if ( len(data) > 0 ):
				#data = data.encode()
				parse_http ( client.getpeername(), server.getpeername(), data )

				slock.acquire()
				print_debug ("  [1] fts acquired slock, it will now forward data from client to server")
				print_debug ("  [1][F] forwarding data to server: {}".format(len(data)) )
				server.sendall( data )
				slock.release()
				print_debug ("  [1] fts released slock, it has finished to forward data from client to server")
				retry=0
				roundd=roundd+1
			else:
				# it means that client closed the connection or it's not sending anything
				#time.sleep(0.1)
				#retry = retry + 1
				#if retry > 2:
				print_debug ("  [1] data is empty! fts is closing! Connection from client has been closed!")
				client_stop.set() # client has closed the connection brah close the connection with the server
				break
		except socket.timeout:
			print_debug ("  [1] Thread fts Timeout reached!")
			clock.release()
			print_debug ("  [1] fts released clock because it has received nothing from client for {} seconds".format(TIMEOUT) )
			time.sleep(0.1) # need to sleep so ftc can lock on socket
			roundd=roundd+1
			retry=retry+1
			#pass
			if (retry > RETRY): 
				print_debug("  [1][!] Retry limit reached!")
				client_stop.set() # probably client has closed connection but did not send any FIN
				break
			else: continue
	print_debug ("[1][!] Forward To Server thread OVER")

# ftc will wait data from server and forward to client
def forward_to_client ( client, server, clock, slock, client_stop, server_stop ):
	
	retry=0
	roundd = 1
	while (not client_stop.is_set()):
		print_debug ("[2] Forward To Client BEGIN\t[round {}] [retry {}]".format(roundd, retry) )
		try:
			slock.acquire()
			print_debug ("  [2] ftc acquired slock, now is waiting for data from server to be forwarded to client")
			print_debug ("  [2] Recv...")
			data = server.recv ( BUF_SIZE )
			#print_debug ( "[2] Received from server:\n", data.decode() )
			slock.release()
			print_debug ("  [2][R] ftc released slock, it received some data from server to be forwarded to client, it could be empty: {}".format(len(data)) )
			if ( len(data) > 0 ):
				#data = data.encode()
				parse_http ( server.getpeername(), client.getpeername(), data )

				clock.acquire()
				print_debug ("  [2] ftc acquired clock, it will forward the data from server to client")
				print_debug ("  [2][F] forwarding data to client: {}".format(len(data)) )
				client.sendall( data )
				clock.release()
				print_debug ("  [2] ftc released clock, it has successfully forwarded data to client")
				roundd=roundd+1
				retry=0
			else:
				# it means server has closed the connection or it's not sending anything
				#time.sleep(0.1)
				#retry = retry + 1
				#if retry > 2: 
				print_debug ("  [2] data is empty! ftc is closing! Connection from server has been closed!")
				server_stop.set()
				break
		except socket.timeout:
			print_debug ("  [2] Thread ftc Timeout reached!")
			slock.release()
			print_debug ("  [2] ftc released slock because it has received nothing from server for {} seconds".format(TIMEOUT))
			time.sleep(0.1)
			roundd=roundd+1
			retry=retry+1
			#pass
			if (retry > RETRY): 
				print_debug("  [2][!] Retry limit reached!")
				server_stop.set() # probably server has closed connection but did not send any FIN
				break
			else: continue
	print_debug ("[2][!] Forward To Client OVER")

def handle_connection_stream ( client, server ):
	try:
		# lock access for client and socket server
		clock = threading.Lock()
		slock = threading.Lock()

		# set sockets to block for tot timelimit seconds, after that they'll raise socket.timeout exception
		client.settimeout ( TIMEOUT )
		server.settimeout ( TIMEOUT )

		# event that signal that server or client has closed the connection
		server_stop = threading.Event()
		client_stop = threading.Event()

		# fts knows when client close the connection but not when server does 
		th1 = threading.Thread( target=forward_to_server, args=[ client,server,clock, slock, client_stop, server_stop ] )  
		th1.setDaemon(True)
		th1.start()

		# ftc knows when server close the connection but not when client does
		th2 = threading.Thread( target=forward_to_client, args=[ client,server,clock, slock, client_stop, server_stop ] )  
		th2.setDaemon(True)
		th2.start()
		# need to wait threads?
		#time.sleep(60)
		
		#th1.join()
		#print_debug ("Thread 1 finished")
		th2.join() # wait for communication with server to be closed
		# aka wait for FTC to terminate  ----> server closed connection

		print_debug ("Thread 2 finished")
		# means server has closed connection with me so i need to close connection with client emulating the closure
		#server_stop.set() # WHAT IF FTS IS IN RECV MODE? OR WORST IS SENDING DATA

		th1.join() # THIS SAVED THE DAY
		print_debug ("Thread 1 finished")
		#client_stop.set()

	except KeyboardInterrupt:
		raise

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
		elif time.time()-begin>timeout*2:
			break
		wait=0
		try:
			data=the_socket.recv(BUF_SIZE)
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

def handle_connection( client, server ): # recv and send could fail?? YES if socket get closed!

	#parser = MyHTMLParser()

	# i should open each session for multiple client connection aka a new server connection for each client
	while True: # repeat till connection got closed from client or server
		try:
			# wait req from client
			client_request = recvall ( client )
			if ( client_request ): # i have received data from client
				#print ('[*] request received from client:\n')
				#print ("request lenght: ", len(client_request) )
				out = parse_http(client_request)
				print(time.time(), "\t", client.getpeername(), "\t-->\t", server.getpeername(), ":\t", out[0])
				'''
				_, headers = client_request.split('\r\n', 1)
				message = email.message_from_file(StringIO(headers))
				headers = dict(message.items())
				pprint.pprint(headers, width=160)
				'''
				#print ("[*] Forwarding to server...")	

				try:
					server.sendall(client_request.encode()) # it fails here? yes, server close connection but i don't see it

					#print ("[*] Waiting for response...")

					server_response = ''
					server_response = recvall ( server ) # what if server close connection aka socket? What if i got to wait more?
					if ( server_response ):
						#print ('[*] Received packet from server:\n')
						#print ("response lenght: ", len(server_response) )
						# what if response is empty?? Should i create a new connection each time? recvall should receive all the data it needs
						re = parse_http( server_response )
						print ( time.time(), "\t", server.getpeername(), "\t-->\t", client.getpeername(), ":\t", re[0] )

						#forward server response to client
						#print ("[*] Forwarding to client...")
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
