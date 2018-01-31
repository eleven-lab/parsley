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
TIMEOUT = 0.4 # waiting time on recv before throwing socket.timeout exception, 0.1
RETRY = 8
DEBUG = 1

def print_debug ( string ):
	
	if (DEBUG == 0) : 
		
		logging.debug ( string )
	else: 
		return

def handle_connection ( client, server ):
	server.settimeout ( TIMEOUT ) # only need timeout from server it could crash or data dont have EOD
	while True:
		try:
			logging.debug("[*] [{}] (1) receiving data from client...".format(time.asctime( time.localtime(time.time()) )) )
			# blocking recv socket on client connection
			try:
				client_data = client.recv ( BUF_SIZE )
			except ( socket.timeout ):
				logging.debug("[!] [{}] Socket timeout!".format(time.asctime( time.localtime(time.time()) )) )
				pass
			# what if client has more data to send?
			# what if recv throws a SSL error like unknown CA? What if client close connection for the same reason? ( i receive a FIN )

			# receive some data: it could be empty meaning a FIN from client which means he finished to send data
			if ( len( client_data ) > 0 ):
				parse_http ( client.getpeername(), server.getpeername(), client_data )


				logging.debug("[*] [{}] (2) sending data to server...".format(time.asctime( time.localtime(time.time()) )) )
				# send received data to server and wait for a response from server
				server.sendall( client_data )
				# what if sending on a closed socket?

				logging.debug("[*] [{}] (3) receiving data from server...".format(time.asctime( time.localtime(time.time()) )) )
				server_data = server.recv( BUF_SIZE )
				# what if listening on a closed connection?

				if ( len( server_data ) > 0 and len( server_data ) != BUF_SIZE ):
					parse_http ( server.getpeername(), client.getpeername(), server_data )

					logging.debug("[*] [{}] (4) sending data to client...".format(time.asctime( time.localtime(time.time()) )) )
					client.sendall( server_data )

					client.settimeout ( TIMEOUT )
				else: # server has finished to send data
					logging.debug("[*] [{}] Received all data from server! FIN".format(time.asctime( time.localtime(time.time()) )) )
					client.sendall( server_data )
					server.settimeout ( None ) # reset to blocking
					time.sleep(0.1)
					# connection with server should be still active
			else:
				logging.debug("[*] [{}] Received all data from client! FIN".format(time.asctime( time.localtime(time.time()) )) )
				server.sendall( client_data )
				time.sleep(0.1)
				break
		except ( socket.error ):
			logging.debug("[!] Socket error!", exc_info=True )
			break


# fts will wait data from client and forward to server
def forward_to_server ( client, server, clock, slock, client_stop, server_stop ):

	#localtime = time.asctime( time.localtime(time.time()) )
	#print ("Local current time :", localtime)

	retry=0
	roundd = 1
	total = 0
	while (not server_stop.is_set()):
		print_debug ( "[1] Forward To Server thread BEGIN\t[round {}] [retry {}]".format(roundd, retry) )
		try:
			clock.acquire()
			print_debug ("  [1] fts acquired clock! Now is waiting for data from client...")
			print_debug ("  [1] Recv...")
			data = client.recv ( BUF_SIZE ) # ssl.SSLError: [SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca ---> connection reset by client browser FIREFOX ---> not catched
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
				total = total + len(data)
			else:
				# it means that client closed the connection or it's not sending anything
				#time.sleep(0.1)
				#retry = retry + 1
				#if retry > 2:
				print_debug ("  [1] data is empty! fts is closing! Data from client is finished!")
				logging.debug("[-] Received empty data ( FIN ) from client which means he has no more data to forward!")
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
				logging.debug("[-] [{}] Retry limit reached! No responses from client maybe he finished or has the connection closed!".format(time.asctime( time.localtime(time.time()) )) )
				print_debug("  [1][!] Retry limit reached!")
				client_stop.set() # probably client has closed connection but did not send any FIN
				break
			else: continue
		except socket.error: # getpeer error, recv error, sendall error
			logging.error ("[!] Error is thread socket handling!", exc_info=True )
			break
	if ( server_stop.is_set() ): logging.debug("[-] Exiting: Received signal from ftc thread that says that server has presumably finished sending data..")
	print_debug ("[1][!] Forward To Server thread OVER")
	logging.info ( "[*] Total data size forwarded to server from client {}".format( total ) )

# ftc will wait data from server and forward to client
def forward_to_client ( client, server, clock, slock, client_stop, server_stop ):
	
	retry=0
	roundd = 1
	total = 0
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
				total = total + len(data)
			else:
				# it means server has closed the connection or it's not sending anything
				#time.sleep(0.1)
				#retry = retry + 1
				#if retry > 2: 
				print_debug ("  [2] data is empty! ftc is closing! No more data from server!")
				logging.debug("[-] Received empty data ( FIN ) from server which means he has no more data to send!")
				server_stop.set()
				break
				#logging.info ( "[*] Total data size forwarded to client from server {}".format( total ) )
				#retry=0
				#roundd=roundd+1
				#total=0
				#continue
		except socket.timeout:
			print_debug ("  [2] Thread ftc Timeout reached!")
			slock.release()
			print_debug ("  [2] ftc released slock because it has received nothing from server for {} seconds".format(TIMEOUT))
			time.sleep(0.1)
			roundd=roundd+1
			retry=retry+1
			#pass
			if (retry > RETRY): 
				logging.debug("[-] [{}] Retry limit reached! No responses from server maybe he finished or has the connection closed!".format(time.asctime( time.localtime(time.time()) )) )
				print_debug("  [2][!] Retry limit reached!")
				server_stop.set() # probably server has closed connection but did not send any FIN
				break
			else: continue
		except socket.error:
			logging.error ("[!] Error is thread socket handling!", exc_info=True )
			break
	if ( client_stop.is_set() ): logging.debug("[-] Exiting: Received signal from fts thread that says that client has presumably finished sending data..")
	print_debug ("[2][!] Forward To Client OVER")
	logging.info ( "[*] Total data size forwarded to client from server {}".format( total ) )

def handle_connection_stream ( client, server ):
	try:
		time.sleep(0.2) # sleep for making sure browser send stuff

		# lock access for client and socket server
		clock = threading.Lock()
		slock = threading.Lock()

		# set sockets to block on recv for tot timelimit seconds, after that they'll raise socket.timeout exception
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

		logging.debug ("Thread 2 finished")
		# means server has closed connection with me so i need to close connection with client emulating the closure
		#server_stop.set() # WHAT IF FTS IS IN RECV MODE? OR WORST IS SENDING DATA

		th1.join() # THIS SAVED THE DAY
		logging.debug ("Thread 1 finished")
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

def handle_connection_dumb( client, server ): # recv and send could fail?? YES if socket get closed!

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
