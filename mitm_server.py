import socket
import ssl
import OpenSSL
import logging
import time
from OpenSSL import crypto, SSL

from cert import *
from utils import *
from connection import *
from threading import Lock

class client_session():
	def __init__( self, client, hostname ):
		self.client = client
		self.hostname = hostname
		self.t = None # thread that is handling the session
		#self.connect = [] # list of servers
		#ss = connect_to_server ( self, hostname ) # return socket with server connection
		#self.connect.append( server )
		#self.server = ss
		self.server = None

	def __repr__(self):
		return '{}: {} {} {}\nhandled by thread: {}\n'.format(self.__class__.__name__, self.client, self.server, self.hostname, self.t )


class clean_sessions_agent ( threading.Thread ):
	def __init__ ( self, sessions, sessions_mutex ):
		super( clean_sessions_agent , self).__init__() # needed: RuntimeError: Thread.__init__() not called

		self.sessions = sessions
		self.mutex = sessions_mutex
		return

	def run ( self ):
		self.clean()

	def clean( self ):
		timeout = 5
		

		while ( True ):
			delete_list = []

			self.mutex.acquire()
			#print ( len( self.sessions ) ) 
			for x in range(0, len( self.sessions ) ) :
				#print ( x )
				if ( self.check_session ( self.sessions[ x ] ) ):
					#logging.debug ( "Cleaning session no.{}".format( x ) )
					#print ( "deleted %d!" % x )
					delete_list.append( x )
					
			d = 0
			for i in delete_list:
				del self.sessions[ x-d ]
				d += 1
			
			self.mutex.release()
			time.sleep( timeout )
	
	def check_session( self, session ):
		# check if thread is stop
		if ( session.t.stopped() ): return True
		else: return False


class mitm_ssl_context():
	def __init__( self, s, certificate ):
		try:
			self.m, self.ctx = self.create_proxy_ssl_context ( s, certificate ) # listening socket and ssl context
			
			self.cert = certificate # path of certificate
			#self.ca = # x509 object of certificate, so i don't need to reopen the file eache time

			#self.print_context()

			self.sessions = [] # list of sessions or connections

			
			self.sessions_mutex = threading.Lock()

			self.sessions_agent = clean_sessions_agent( self.sessions, self.sessions_mutex )
			self.sessions_agent.setDaemon ( True )
		except Exception:
			logging.error ( "Error on initializating mitm server!", exc_info = True )
			raise
		

	def print_context ( self ):
		logging.info ( self.ctx, self.m, self.cert )

	def create_proxy_ssl_context ( self, s, cert ):
		try:
			# https://docs.python.org/3/library/ssl.html#ssl.create_default_context
			ctx = ssl.create_default_context() # PROTOCOL_SSLv23, PROTOCOL_TLSv1, ssl.PROTOCOL_TLS_SERVER

			# https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_cert_chain
			ctx.load_cert_chain( certfile=cert, keyfile=cert )

			ctx.check_hostname = False # without this context need a hostname for the server

			# https://docs.python.org/3/library/ssl.html#ssl.SSLContext.set_servername_callback
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
		self.sessions_agent.start()

		while ( True ):
			try:
				logging.debug("Waiting for client connections..")
				c, addr = self.m.accept() # server_callback methos
				index = self.search_for ( c ) #  search for client session

				# WHAT IF IT HAS MULTIPLE ACTIVE CONNECTIONS?? sockets are differents mormon
				self.handle_client_session( self.sessions[index] )

				# POP SESSION WHEN IS FINISHED! FOR NOW WAIT THE THREAD TO FINISH
				# del self.sessions[index]

			except Exception as e: # exception in accepting the connection OR handling it
				f = self.handle_exception ( e )
				#logging.error( "Error in accepting the connection!", exc_info=True )
				if ( f == 0 ):
					continue
				elif ( f == 1 ):
					raise
		return 

	def search_for ( self, c ):# what is i? should client socket
		self.sessions_mutex.acquire()
		for i, sess in enumerate(self.sessions):
			if c == sess.client:
				self.sessions_mutex.release()
				return i
		self.sessions_mutex.release()

	def handle_client_session ( self, session ):
		#client = session.client
		#server = session.server

		# create a thread for handle the session
		#logging.debug ( "Handling connection between\nCLIENT: {}\nSERVER: {}".format(client,server) )
		#sa = connection_agent( client, server )
		#sa.setDaemon ( True )
		#session.t = sa

		#logging.debug("\nStarting Thread\n-------------------------------------------------------")
		session.t.start( ) # dont wait for finish

		#session.t.join() # wait for testing
		#logging.debug("-------------------------------------------------------\nThread finished\n")
		return

	def connect_to ( self, hostname ):
		s = create_socket()
		#logging.debug ("SOCKET: {}".format( s ) )

		s = connect_to_server ( s, hostname, 443 )

		#logging.debug ("SERVER: {}".format( s ) )
		#s.connect (( hostname, 443 ))

		return s # return socket

	# https://docs.python.org/3/library/ssl.html#ssl.SSLContext.set_servername_callback
	def server_callback ( self, c,hostname,ctx ):# ctx connessione con mitm e client
		logging.info("\n{}\nclient wants to connect to {}".format( c, hostname ))

		cl = client_session( c, hostname )
		cl.server = self.connect_to ( hostname )

		sa = connection_agent( cl.client, cl.server )
		sa.setDaemon ( True )
		cl.t = sa

		self.sessions_mutex.acquire()
		self.sessions.append( cl ) # append client_session object
		self.sessions_mutex.release()

		# self.hostname = hostname
		name = hash_string( hostname )
		name = "certificates/" + name

		if ( not os.path.exists( name ) ):
			logging.info ( "Creating file {}".format( name ) )
			server_cert = get_cert_from_endpoint ( hostname, 443 ) # get end entity certificate from server, base64 format
			
			with open(self.cert, "rb") as my_cert_file:
				my_cert_text = my_cert_file.read()
				key = crypto.load_privatekey ( crypto.FILETYPE_PEM, my_cert_text ) # get private key
				ca_cert = x509_cert( my_cert_text )

			name = spoof_cert ( x509_cert(server_cert) , ca_cert, key )
			name = "certificates/" + name
		
		
		'''
		Load a private key and the corresponding certificate. The certfile string must be the path to a single file in PEM format containing the certificate as well as any number of CA certificates needed to establish the certificate’s authenticity. The keyfile string, if present, must point to a file containing the private key in. Otherwise the private key will be taken from certfile as well. See the discussion of Certificates for more information on how the certificate is stored in the certfile.
		'''
		
		cc = ssl.create_default_context() 
		cc.check_hostname = False # ValueError: check_hostname requires server_hostname
		#cc.verify_mode = ssl.CERT_NONE

		# https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_cert_chain
		cc.load_cert_chain( certfile = name, keyfile = self.cert )

		# https://stackoverflow.com/questions/41996833/using-ssl-context-set-servername-callback-in-python
		c.context = cc
		#cc.wrap_socket( c, server_side=True, do_handshake_on_connect=True ) 
		
		return None

	def handle_exception( self, e ): # TODO
		logging.error( "Error: {}".format(e), exc_info=True )
		return 0

