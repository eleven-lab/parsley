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
- UDP support
- mitm gateway
- parsers for data

- configuration of certificate cloning ( dynamic )
- iptables cleanup
- parsing of different application protocols
- handling of multiple client connections and multiple threads
- handle listening ports on mitm and service emulation
- make the project more modular 
- handling connection reset from server or client
- do a better formatting 
- do a logger
- handle data without EOD
- handle exceptions better
