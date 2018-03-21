import socket
import ssl
import logging
import time

import errno

import OpenSSL
from OpenSSL import crypto, SSL

def wrap_ssl_socket ( s ): # socket should be SOCK_STREAM, to server socket
	try:
		s = ssl.wrap_socket ( s, server_side=False, keyfile=None, certfile=None, cert_reqs=ssl.CERT_NONE )
		#logging.debug ( "SSL SOCKET:{}".format( s ) )
		return s
	except Exception:
		logging.error ( "Error in wrapping ssl socket!", exc_info=True )
		raise

def connect_to_server( s, ip, port ):
	
	logging.debug("Connecting to server {}:{}...".format(ip,port))
	
	if ( port == 443 ):
		logging.debug("Doing TLS handshake...")
		s = wrap_ssl_socket( s )

	while ( True ):
		try:
			# maybe it should connect to IP instead of name host?
			conn = s.connect( (ip, port) )
			if ( conn == -1 ):
				raise Exception
			else:
				logging.debug( "[{}] Connection enstablished!\n{}\n".format(time.asctime( time.localtime(time.time()) ), s ) )
				return s

		except Exception as e:
			logging.error ( "Error {} in connecting to {}:{}!".format(e,ip,port), exc_info=True )
			
			# OSError: [Errno 9] Bad file descriptor
			if ( e.errno == 9 ):
				continue
			else:
				raise

	return
	
def create_socket():
	s = None
	try:
		s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
		if ( s == -1 ):
			raise Exception
		else: return s
	except Exception:
		logging.error ( "Error on creating socket", exc_info=True )
		raise

def bind_socket ( s, ip, port ):
	try:
		s.bind ((ip,port))
		return
	except Exception:
		logging.error ( "Error on binding socket", exc_info=True )
		raise

def close_socket( s ):
	if ( s != None ):
		try:
			s.close()
		except Exception:
			logging.error ( "Error on closing socket {}".format( s ), exc_info=True )
			raise

