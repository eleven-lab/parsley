# parsley

parsley is a TCP/IP man in the middle. It use Python3 and scapy for ARP spoof the real server in a local network.

parsley v0.1<br/>


![alt text](banner.jpg)


## Installation
```
   $git clone https://github.com/eleven-lab/parsley
   $cd parsley
   $sudo pip install -r requirements.txt
   $sudo chmod +x parsley.py
   $sudo python3 parsley.py -h
```

## Basics
```
usage: 
 Network interface:     -i <INTERFACE> or --interface <INTERFACE> 
 Target IP Address:     -t <TARGET> or --target <TARGET> 
 Gateway IP Address:	-s <SERVER> or --server <GATEWAY>

examples:
  $sudo ./parsley.py -i eth0 -t 10.0.0.3 -s 10.0.0.5

```

## ToDo
- UDP support for stream of data
- mitm gateway
- different parsers for different TCP based application protocols

- Certificate cloning should be configurable
- iptables cleanup should erase only added rules not all nat table
- handling of multiple client connections and multiple threads
- handle listening ports on mitm and different services ( ports )
- make the project more modular 
- handling connection reset from server or client
- do a better formatting of the output
- do a better logging
- log stuff into a file
- handle data without EOD
- handle exceptions better
- if the server does not have a certificate the program will stall without throwing an exception
- accept spoofed IP packets without ip tables

## Limitations
It utilize SOCK_STREAM sockets which are the only one that can be wrapped in a ssl socket.

