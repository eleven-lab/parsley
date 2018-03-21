# parsley

parsley is a TCP/IP man in the middle. It use Python3 and scapy for ARP spoof the real server in a local network.

parsley v0.2<br/>


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
 Gateway IP Address:	-s <SERVER> or --server <SERVER>

examples:
  $sudo ./parsley.py -i eth0 -t 10.0.0.3 -s 10.0.0.5

```

## ToDo

## Limitations
It utilize SOCK_STREAM sockets which are the only one that can be wrapped in a ssl socket.

## bugs


