# parsley

parsley is a TCP/IP man in the middle. It use Python3 and scapy for ARP spoof the real server in a local network.

parsley v0.2<br/>

![alt text](banner.jpg)

## Goals
* Provide mitm ssl proxy to intercept https information from a target
* Intercept TCP communication from a target and emulate general TCP services, such http and https

## Usage
```
   $git clone https://github.com/eleven-lab/parsley
   $cd parsley
   $sudo pip install -r requirements.txt
   $sudo chmod +x parsley.py
   $sudo python3 parsley.py -h

   usage: 
     Network interface:     	-i <INTERFACE> or --interface <INTERFACE> 
     Target IP Address:     	-t <TARGET> or --target <TARGET> 
     Gateway IP Address:	-s <SERVER> or --server <SERVER>

   example:
     $sudo python3 parsley.py -i eth0 -t 10.0.0.3 -s 10.0.0.5
```

## ToDo
- [ ] Make mitm attack faster
- [X] Handle more connections for a client
- [ ] Handle more clients or targets
- [ ] Handle communication errors in a proper way
- [ ] Define parsers and make output readable
- [ ] Handle connections from clients that doesn't support SNI
- [ ] Make a beautiful and colorized logger
- [ ] Define a debugging logic for all the threads
- [ ] Define a proper cleanup procedure for iptables rules
- [ ] Catch relevant informations ( username, passwords.. ) in client connections
- [ ] Make certificate automatic creation more personalizable

## Limitations
* It utilize SOCK_STREAM sockets which are the only one that can be wrapped in a ssl socket. In few words it can handle only TCP connections, not UDP.
* Use of iptables for catch client connections

## Future implementations
* ssl strip
* Parsers for many TCP protocols
* Add more ARP spoofing techniques




