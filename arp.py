#!/usr/bin/python

import socket
import struct

class Ethernet(object):
    def __init__(self):
        self.dst = None
        self.src = None
        self.type = None


class Arp(object):
    def __init__(self):
        self.htype = None
        self.ptype = None
        self.hsize = None
        self.psize = None
        self.op = None
        self.shwa = None
        self.sipa = None
        self.thwa = None
        self.tipa = None
        self.padd = None

eth = Ethernet()

# broadcast
eth.dst = b'\xff\xff\xff\xff\xff\xff'
eth.src = b'\x00\x00\x00\x00\x00\x02'

eth.etype = 0x0806

arp = Arp()

arp.htype = 0x01
arp.ptype =0x0800
arp.hsize = 0x06 
arp.psize = 0x04 
arp.op = 0x0001

# request
arp.shwa = b'\x00\x00\x00\x00\x00\x02'
arp.sipa = socket.inet_aton('192.168.2.1')
arp.thwa = b'\x00\x00\x00\x00\x00\x00'
arp.tipa = socket.inet_aton('192.168.2.100')


frame = struct.pack('!6s6sH', eth.dst, eth.src, eth.etype)
arpf = struct.pack('!HHBBH6s4s6s4s', arp.htype, arp.ptype, arp.hsize, arp.psize, arp.op, arp.shwa, arp.sipa, arp.thwa, arp.tipa)
packet = frame + arpf

socket2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
socket2.bind(('r0-eth2', 0)) # use interface of your choice
socket2.send(packet)