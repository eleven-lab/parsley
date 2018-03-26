# parsley

parsley is a TCP/IP man in the middle. It use Python3 and scapy for ARP spoof the real server in a local network.

parsley v0.2<br/>


![alt text](banner.jpg)


## Usage
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
mitm troppo lento capire dove è il problema
gestire più comunicazioni contemporaneamente
gestire più client vittima
gestire errori di comunicazione non previsti
rendere l'output più leggibile
fare un parser di richieste POST o http decente
gestire connessioni a server senza l'utilizzo SNI o hostname
fare un logger decente e bello colorato

## Limitations
It utilize SOCK_STREAM sockets which are the only one that can be wrapped in a ssl socket.

## Future
ssl strip
sniff e parsers di altri protocolli


