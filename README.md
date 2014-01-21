python-raw-sockets
==================

Is a simple experiment to try implement the basic level details (Ethernet, IP and TCP protocols) in python for fun.

Example: Sending a nonsensical ARP frame on my Wi-Fi. 
-------------------------------------------------------
Example code:
```python
#!/usr/bin/env python

from socket import socket, SOCK_RAW, AF_PACKET
from rawsocket.linklayer import Ethernet

class PFPacketSender:
    def __init__(self, interface):
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((interface, 0))

    def send(self, frame):
        self.sock.send(frame)

    def __str__(self):
        return "PF_PacketSender"


class Logger:
    ....
    ....

def parse_args():
    ....
    ....

def main():
    args = parse_args()
    log = Logger().get_logger("main")
    log.info("Starting....")
    src_mac = None
    with open("/sys/class/net/%s/address" % args.interface) as f:
        src_mac = f.read().strip()

    ether = Ethernet(log, PFPacketSender(args.interface), src_mac)
    ether.xmit("ARP", hex(123))


if __name__ == '__main__':
    main()

```

Execution
```
$ python bin/example.py
2014-01-21 23:07:42,719 - main - INFO - Starting....
2014-01-21 23:07:42,719 - main - DEBUG - dst mac addr: ff:ff:ff:ff:ff:ff
2014-01-21 23:07:42,720 - main - DEBUG - src mac addr: 08:00:27:d5:42:6c
2014-01-21 23:07:42,720 - main - DEBUG - Attempting to load ether type for 'ARP'
2014-01-21 23:07:42,720 - main - INFO - EtherProto: ARP: sending 60  bytes through PF_PacketSender
2014-01-21 23:07:42,721 - main - DEBUG - Message: ffffffffffff080027d5426c080630783762000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

The resulting frame as captured by tshark
```
Frame 1: 60 bytes on wire (480 bits), 60 bytes captured (480 bits) on interface 0
    Interface id: 0
    Encapsulation type: Ethernet (1)
    Arrival Time: Jan 21, 2014 23:06:48.532695000 SAST
    [Time shift for this packet: 0.000000000 seconds]
    Epoch Time: 1390338408.532695000 seconds
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 60 bytes (480 bits)
    Capture Length: 60 bytes (480 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:arp]
Ethernet II, Src: 08:00:27:d5:42:6c (08:00:27:d5:42:6c), Dst: ff:ff:ff:ff:ff:ff (ff:ff:ff:ff:ff:ff)
    Destination: ff:ff:ff:ff:ff:ff (ff:ff:ff:ff:ff:ff)
        Address: ff:ff:ff:ff:ff:ff (ff:ff:ff:ff:ff:ff)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Source: 08:00:27:d5:42:6c (08:00:27:d5:42:6c)
        Address: 08:00:27:d5:42:6c (08:00:27:d5:42:6c)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: ARP (0x0806)
    Padding: 000000000000000000000000000000000000000000000000...
Address Resolution Protocol (reserved)
    Hardware type: Unknown (12408)
    Protocol type: Unknown (0x3762)
    Hardware size: 0
    Protocol size: 0
    Opcode: reserved (0)
```

Why is the payload not 123? 
* It's just the hex encoding of the string '0x7b' which is the hex represention of the decimal 123...

```python
hex(123)
> '0x7b'

[hex(ord(a)) for a  in hex(123)]
> ['0x30', '0x78', '0x37', '0x62']
```
