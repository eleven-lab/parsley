import socket
import ssl
import OpenSSL
import logging
from OpenSSL import crypto, SSL

from cert import *
from utils import *
from connection import *

class client_session():
	def __init__( self, client, hostname ):
		self.client = client
		self.hostname = hostname
		#self.connect = [] # list of servers
		#ss = connect_to_server ( self, hostname ) # return socket with server connection
		#self.connect.append( server )
		#self.server = ss
		self.server = None

	def __repr__(self):
		return '{}: {} {} {}'.format(self.__class__.__name__, self.client, self.server, self.hostname)


class mitm_ssl_context():
	def __init__( self, s, certificate ):
		self.m, self.ctx = self.create_proxy_ssl_context ( s, certificate ) # listening socket and ssl context
		
		self.cert = certificate # path of certificate
		#self.print_context()

		self.sessions = [] # list of sessions or connections

	def print_context ( self ):
		logging.info ( self.ctx, self.m, self.cert )

	def create_proxy_ssl_context ( self, s, cert ):
		try:
			ctx = ssl.create_default_context() # PROTOCOL_SSLv23, PROTOCOL_TLSv1, ssl.PROTOCOL_TLS_SERVER

			ctx.load_cert_chain( certfile=cert, keyfile=cert )

			ctx.check_hostname = False # without this context need a hostname for the server
			ctx.set_servername_callback ( self.server_callback )
			ctx.verify_mode = ssl.CERT_NONE # ssl.CERT_REQUIRED # this was important otherwise ERROR i want client certificate

			s = ctx.wrap_socket( s, server_side=True, do_handshake_on_connect=True ) # server_side=True

			return s, ctx 
		except Exception:
			logging.error ( "Error on wrapping socket", exc_info=True )
			raise

	def listen_for_connections ( self, CONN ):
		try:
			logging.info ("Listening for connections...")
			self.m.listen ( CONN )
			return
		except Exception:
			logging.error( "Error on listening on mitm socket!",exc_info=True )
			raise

	def accept_client_connections ( self ):
		while ( True ):
			try:
				logging.debug("Waiting for connections..")
				c, addr = self.m.accept() # server_callback methos
				index = self.search_for ( c ) #  search for client session

				# WHAT IF IT HAS MULTIPLE ACTIVE CONNECTIONS?? sockets are differents mormon
				self.handle_client_session( self.sessions[index].client, self.sessions[index].server )

				# POP SESSION WHEN IS FINISHED! FOR NOW WAIT THE THREAD TO FINISH
				del self.sessions[index]

			except Exception as e: # exception in accepting the connection OR handling it
				f = self.handle_exception ( e )
				#logging.error( "Error in accepting the connection!", exc_info=True )
				if ( f == 0 ):
					continue
				elif ( f == 1 ):
					raise
		return 

	def search_for ( self, c ):# what is i? should client socket
		for i, sess in enumerate(self.sessions):
			if c == sess.client:
				return i

	def handle_client_session ( self, client, server ):
		# create a thread for handle the session
		logging.debug ( "Handling connection between\nCLIENT: {}\nSERVER: {}".format(client,server) )
		sa = connection_agent( client, server )
		sa.setDaemon ( True )
		logging.debug("\nStarting Thread\n-------------------------------------------------------")
		sa.start( ) # dont wait for finish

		sa.join() # wait for testing
		logging.debug("-------------------------------------------------------\nThread finished\n")
		return

	def connect_to ( self, hostname ):
		s = create_socket()
		#logging.debug ("SOCKET: {}".format( s ) )

		s = connect_to_server ( s, hostname, 443 )

		#logging.debug ("SERVER: {}".format( s ) )
		#s.connect (( hostname, 443 ))

		return s # return socket

	def server_callback ( self, c,hostname,ctx ):# ctx connessione con mitm e client
		logging.info("client wants to connect to {}".format( hostname ))

		cl = client_session( c, hostname )
		cl.server = self.connect_to ( hostname )

		self.sessions.append( cl ) # append client_session object

		# self.hostname = hostname
		
		server_cert = get_cert_from_endpoint ( hostname, 443 ) # get end entity certificate from server
		
		with open(self.cert, "rb") as my_cert_file:
			my_cert_text = my_cert_file.read()
			ca_cert = x509_cert( my_cert_text )

		name = spoof_cert ( x509_cert(server_cert) , ca_cert )

		name = "certificates/" + name
		ctx.load_cert_chain( certfile = name, keyfile = name )
		
		return None

	def handle_exception( self, e ): # TODO
		logging.error( "Error: {}".format(e), exc_info=True )
		return 0

