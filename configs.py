from argparse import ArgumentParser
from scapy.all import *
import netifaces as ni

import os
import socket
import logging

from cert import create_cert
def set_configs():
	try:
		parser = ArgumentParser()

		parser.add_argument ( "-d", "--debug", help="enable debug mode.")

		parser.add_argument ( "-t", "--target", required=True, type=str, help="The target IP." )
		parser.add_argument ( "-s", "--server", required=True, type=str, help="The server IP to spoof." )
		parser.add_argument ( "-i", "--interface", required=True, type=str, help="The interface to use." )

		parser.add_argument ( "-c", "--certificate", type=str, default="localhost.pem", help="Path to the ca certificate to use, if none the standard certificate will be used. Certificate should include also the private key." )

		# parse command line
		args = parser.parse_args()
		
		sanitize_args ( args )

		conf = {
			'certificate' : args.certificate,  
			'mitm' : {
				'ip': ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr'],
				'mac': ni.ifaddresses(args.interface)[ni.AF_LINK][0]['addr'],
			},
			'target' : {
				'ip':args.target,
				'mac':ip_to_mac( args.target, args.interface ),
			},
			'server' : {
				'ip':args.server,
				'mac':ip_to_mac( args.server, args.interface ),
			},
			'interface' : args.interface
		}
		logging.info(conf)
		return conf
	except Exception:
		#logging.error( exc_info=True )
		raise

def sanitize_args( args ):
	'''
	logging.info ( "{} {}".format(args, type( args )) )
	for k in args.__dict__:
		logging.info( args.__dict__[k] )
	'''
	check_ip(args.server)
	check_ip(args.target)
	check_int(args.interface)
	check_file( args.certificate )
	return

def check_file ( fname ):
	if fname.endswith('.pem'):
		if ( fname == "localhost.pem" ):
			if os.path.isfile(fname):
				return
			else:
				logging.warning ( "{} does not exist! Recreating one..".format(fname) )
				create_cert()
		else: # filename specified
			if os.path.isfile(fname):
				return
			else:
				logging.error ( "BAD_CERT: {} does not exist!".format(fname) )
				raise NameError ( "BAD_CERT" )
	else:
		logging.error ( "BAD_CERT: {} should be a .pem file!".format(fname) )
		raise NameError ( "BAD_CERT" )

def check_ip ( IP ):
	try:
		parts = IP.split(".")
		if len(parts) != 4:
			raise socket.error

		socket.inet_aton( IP )
		# legal

		return
	except socket.error:
		# Not legal
		logging.error ( "BAD_IP: {} is not a valid IP address!".format(IP) )
		raise NameError ( "BAD_IP" )

def check_int ( interface ):
	try:
		ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
		return
	except Exception:
		logging.error ( "BAD_INTERFACE: The interface {} does not exist!".format(interface) )
		raise NameError ( "BAD_INTERFACE" )

def ip_to_mac ( IP, interface ):
	try:
		logging.info ( "Finding mac for IP address {}".format(IP) )
		arp_rq = ARP()
		arp_op = 1 # honest arp request
		arp_rq.hwdst = "ff:ff:ff:ff:ff:ff"
		arp_rq.pdst = IP

		ans, unans = sr ( arp_rq, retry=4, timeout=1, iface = interface, verbose=0 )

		# check if IP does not exist
		for snd,rcv in ans:
			mac = rcv[ARP].underlayer.src
			logging.info ( "Found {}".format(mac) )
			return mac

		logging.warning ( "It seems IP address is unreachable. No mac found. Exiting.." )
		sys.exit()

	except OSError as ose:
		if ( ose.errno == 19 ):
			logging.error ("The interface {} does not exist!".format(interface))
			#print ( traceback.format_exc() )
			return
		else:
			logging.error ("{} is not a valid IP address!".format(IP) )
			#print ( traceback.format_exc() )
			return
	except socket.error:
		logging.error ( exc_info=True )
		return
