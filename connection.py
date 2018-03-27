import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR, IPPROTO_IP
import ssl
import logging
import threading

import errno
import time

from parsers.http import *

BUF_SIZE = 8192
TIMEOUT = 0.2 # waiting time on recv before throwing socket.timeout exception, 0.1

class connection_agent ( threading.Thread ):
	def __init__(self, client, server ):
		super(connection_agent, self).__init__()
		self._stop_event = threading.Event()

		self.client = client
		self.server = server

	def stop(self):
		self._stop_event.set()

	def stopped(self):
		return self._stop_event.is_set()

	def run( self ):
		self.handle_connection( self.client, self.server )

	def handle_connection ( self, client, server ):
		#server.settimeout ( TIMEOUT ) # only need timeout from server it could crash or data dont have EOD
		server_fin = 0
		client_fin = 0
		#logging.debug ( "{}\n{}".format(client, server) )
		client.settimeout ( 0 ) # set non blocking socket client
		server.settimeout ( 0 ) # set non blocking server socket
		while True:

			# get client data
			client_fin, client_data = self._Recv ( client )

			if ( client_fin==1 ): # presumably finished of sending request
				#logging.debug("[{}] client finished sending data".format(time.asctime( time.localtime(time.time()) )) )
				server.settimeout ( 0 )
				client.settimeout ( 0 ) # set non blocking socket client, prob he has nothing to send till it receives all the stuff from the server
				client_fin = 0
			elif ( client_fin==2 ): # close connection from client
				#logging.info("[{}] client closed the connection".format(time.asctime( time.localtime(time.time()) )) )
				break

			if ( client_data != -1 ): # RECEIVED SOMETHING FROM CLIENT
				parse_http ( client.getpeername(), server.getpeername(), client_data )

				#logging.debug("[{}] (2) sending data to server...".format(time.asctime( time.localtime(time.time()) )) )
				self._Sendall( server, client_data ) # this will send ALSO FIN by client
				
			server_fin, server_data = self._Recv( server )
			
			if ( server_data != -1 ): 
				parse_http ( server.getpeername(), client.getpeername(), server_data )
				#logging.debug("[{}] (4) sending data to client...".format(time.asctime( time.localtime(time.time()) )) )
				self._Sendall( client, server_data ) # server didn't sent anything

			if ( server_fin==1 ):
				#logging.debug("[{}] server has finished to send data".format(time.asctime( time.localtime(time.time()) )) )
				server.settimeout ( 0 ) # None = blocking, 0 = non blocking
				client.settimeout ( 0 ) # non blocking ---> wait for further requests
				server_fin = 0
			elif ( server_fin==2 ):
				#logging.info("[{}] server has closed the connection".format(time.asctime( time.localtime(time.time()) )) )
				break
		client.close()
		server.close()
		self.stop()

	def _Recv ( self, s ):
		
		try:
			data = s.recv ( BUF_SIZE )
			
			if ( len( data ) == 0 ): #FIN by endpoint peer --> When a stream socket peer has performed an orderly shutdown, 
				return ( 2, data ) # empty
			elif ( len( data ) < BUF_SIZE ): #FIN by endpoint peer --> not true, only finished to send data this does not mean that it wants to close connection
				
				return ( 1, data )
			else:
				return ( 0, data )
				
		except ssl.SSLError:
			return (0,-1)	
		except socket.error: # data is -1 an error occurred
			return (0,-1)
		except socket.timeout: # (timeout) block socket will raise this exception ---> ONLY IF A CERTAIN TIMEOUT IS SET
			#logging.error ( "Socket reached timeout!" )
			return (0,-1)

	def _Sendall ( self, s, data ):
		try:
			s.settimeout( TIMEOUT )
			e = s.sendall( data ) # ensure that all data to be send is actually received ( ACK ) by endpoint peer
			s.settimeout( 0 )
			return e
		except ssl.SSLError:
			#logging.error ( "ssl.SSLError on SENDING data!", exc_info=True )
			return (0,-1)
		except socket.error:
			#logging.error ( "socket.error on SENDING data!", exc_info=True )
			return (0,-1)
		except socket.timeout:
			#logging.error ( "socket.timeout Error on SENDING data!", exc_info=True )
			return (0,-1)


