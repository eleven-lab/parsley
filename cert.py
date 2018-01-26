import ssl
import OpenSSL
from OpenSSL import crypto, SSL
from os.path import exists, join
from io import open
import traceback
import time

KEYFILE = 'server_key.pem'
CERTFILE = 'server_cert.pem'

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


def clone_certificate ( cert ):
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

def get_cert_from_endpoint(server, port=443):
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
