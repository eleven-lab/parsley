import ssl
import OpenSSL
from OpenSSL import crypto, SSL
from os.path import exists, join
from io import open

import logging 
import os

from utils import hash_string

def create_cert():
	CERTFILE = "localhost.crt"
	KEYFILE = "localhost.key"
	# if certificate from a certain server already exist? 
	if not exists(join(CERTFILE)) \
	or not exists(join(KEYFILE)):
		try:
			logging.info ("Creating server key and cert..")

			#create key pair
			k = crypto.PKey()
			k.generate_key(crypto.TYPE_RSA, 1024)

			#create self signed certificate
			cert = crypto.X509()
			cert.get_subject().CN = "localhost"
			#cert.get_subject().C = raw_input("Country: ")
			#cert.get_subject().ST = raw_input("State: ")
			#cert.get_subject().L = raw_input("City: ")
			#cert.get_subject().O = raw_input("Organization: ")
			#cert.get_subject().OU = raw_input("Organizational Unit: ")

			cert.set_serial_number(1000) # Serial should be dynamic
			
			cert.gmtime_adj_notBefore(0)
			cert.gmtime_adj_notAfter(10*365*24*60*60)

			# You can pass the key file (.key) for anything that needs to validate a connection to the server, but the certificate (.crt) must remain private.
			cert.set_pubkey(k)
			cert.set_issuer(cert.get_subject()) # autosigned aka root CA ---> equal to subject of this certificate --> issuer=subject

			# Sign the key with the public key using SHA-256 hash.
			cert.sign(k, 'sha256')

			with open('localhost.pem', 'wb') as outfile:
				outfile.write( crypto.dump_certificate(crypto.FILETYPE_PEM, cert) )
				outfile.write( crypto.dump_privatekey (crypto.FILETYPE_PEM, k   ) )

			#create files
			#open(join(".", CERTFILE), "wb").write(
			#crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

			#open(join(".", KEYFILE ), "wb").write(
			#crypto.dump_privatekey (crypto.FILETYPE_PEM, k   ))

			#command = "cat localhost.crt localhost.key > localhost.pem"
			#os.system ( command )
		except Exception:
			logging.error("Error in creating the certificate!", exc_info=True )
			raise Exception
	else:
		logging.info ("Certificate and key for server already exist.." ) 

def check_cert_validity ( cert ):
	return

def spoof_cert ( server_cert, ca_cert, key ): # x509 Objects not strings
	CN = server_cert.get_subject().commonName
	print ( CN )
	#CERTFILE = "%s_cert.pem" % CN
	CERTFILE = hash_string ( CN )
	cert_dir = "certificates/"
	temp = cert_dir + CERTFILE

	# set issuer of server_cert with subject of ca_cert
	print ( ca_cert.get_subject() )
	server_cert.set_issuer( ca_cert.get_subject() )
	print ( server_cert.get_issuer() )

	server_cert.set_pubkey( ca_cert.get_pubkey() )

	# sign the certificate using ca_cert key
	#server_cert.sign ( ca_cert.get_pubkey(), 'sha256' )
	#key = crypto.load_privatekey ( crypto.FILETYPE_PEM, ca_cert )
	server_cert.sign ( key, 'sha256' )

	# dump new certificate in directory
	open(join(cert_dir, CERTFILE), "wb").write(
	crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))

	return CERTFILE
	

def x509_cert ( cert ):
	# loading certificate in x509 object
	# Load a certificate (X509) from the string buffer encoded with the type type.
	
	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
	return x509

def get_cert_from_endpoint(server, port=443):
	try:
		# returns it as a PEM-encoded string ---> # PEM formatted key, the base64 encoded x509 ASN.1 key.
		cert = ssl.get_server_certificate((server, port))
	except Exception:
		#log.error('Unable to retrieve certificate from {0}'.format(server))
		logging.error ( "Error in getting server certificate! Maybe it does not provide a ssl service!" )
		cert = None
	if not cert:
		return None
	return cert

