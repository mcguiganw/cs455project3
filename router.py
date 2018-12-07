import socket, sys
from struct import *

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

# Convert IP to str[]
def IPIFY(a) :
    return a.split(".")

# Convert IP into string
def STRINGIFY(a) :
    x = a.split(".")
    ret = ""
    for el in x:
        ret = ret + chr(int(el))
    return ret

# Create a AF_PACKET type raw socket
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except Exception as msg:
    print('Socket could not be created. Error Code : ' + repr(msg))
    sys.exit()

eth_s1 = chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x01)
eth_s2 = chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x02)
eth_s3 = chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x03)
eth_udest = chr(0xFF) + chr(0xFF) + chr(0xFF) + chr(0xFF) + chr(0xFF) + chr(0xFF)

socket1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
socket1.bind(("r0-eth1", 0))
socket2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
socket2.bind(("r0-eth2", 0))
socket3 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
socket3.bind(("r0-eth3", 0))

sockets = {socket1 : eth_s1, socket2 : eth_s2, socket3 : eth_s3}
'''
builder = None
with open("createNet.py", "r") as network:
    builder = network.read()
sockets = []
lines = builder.splitlines()
for line in lines:
    line = line.split("(")
    if(len(line) <= 1):
        continue
    check = line[0].split(".")
    if(len(check) <= 1):
        continue
    check = check[1]
    if check == "intf":
        HN = line[1].split("'")
        print(HN)
        if(len(HN) <= 1):
            continue
        HN = HN[1]
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        try:
            sock.bind((HN, 0))
            sockets.append(sock)
        except:
            print("OOPS")
            continue

'''
# IP Forward table
ip_table = {}

# Arp table
arp_table = {}

# Buffer queue
packet_queue = []


# It is better to do this project using OOP, defining a class for each layer
class Ethernet(object) :
    def __init__(self) :
        self.dst = None
        self.src = None
        self.net_protocol = None
        self.payload = None

    def package(self) :
        return pack('!6s6sH', self.dst, self.src, socket.htons(self.net_protocol))

class ARP(object) :
    def __init__(self) :
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
        self.payload = None

    def package(self) :
        return pack('!HHBBH6s4s6s4s', self.htype, self.ptype, self.hsize, self.psize, self.op, self.shwa, STRINGIFY(self.sipa), self.thwa, STRINGIFY(self.tipa))

class IP(object):
    def __init__(self) :
        self.version = None
        self.ihl = None
        self.frags = None
        self.length = None
        self.ident = None
        self.ttl = None
        self.protocol = None
        self.csum = None
        self.saddr = None
        self.daddr = None
        self.payload = None

    def package(self) :
        return pack('!BBHHHBBH4s4s', self.version*16 + self.ihl, self.ihl, self.length, self.ident, self.frags, self.ttl, self.protocol, self.csum, STRINGIFY(self.saddr), STRINGIFY(self.daddr))
        
class TCP(object):
    def __init__(self) :
        self.sport = None
        self.dport = None
        self.sequence = None
        self.ack = None
        self.doff = None
        self.flags = None
        self.wind = None
        self.csum = None
        self.UP = None
        self.data = None

    def package(self) :
        pc = pack('!HHLLBBHHH', self.sport, self.dport, self.sequence, self.ack, (self.doff << 4) & self.flags, self.flags, self.wind, self.csum, self.UP)
        return pc + ("" if data is None else "".join(data))

class UDP(object):
    def __init__(self) :
        self.sport = None
        self.dport = None
        self.length = None
        self.csum = None
        self.data = None

    def package(self) :
        pc = pack('!HHHH', self.sport, self.dport, self.length, self.csum)
        return pc + ("" if data is None else "".join(data))

class ICMP(object):
    def __init__(self) :
        self.type = None
        self.code = None
        self.csum = None
        self.data = None

    def package(self) :
        pc = pack('!BBH', self.type, self.code, self.csum)
        return pc + ("" if data is None else "".join(data))
    
# You may define IP, TCP, UDP, ICMP like above

def packAndSend(eth, sock):
    packet = ""
    while eth is not None:
        print("Packing layer")
        packet = packet + eth.package()
        if hasattr(eth, "payload"):
            eth = eth.payload
        else:
            eth = None
    print("Sending")
    return sock.send(packet)

# Converts IP string to integer for IP Table
def convertIP(IP):
    IPT = IPIFY(IP)
    a = int(IPT[0])
    b = int(IPT[1])
    c = int(IPT[2])
    d = int(IPT[3])

    ret = a*2**24 + b*2**16 + c*2**8 + d
    return ret

# Finds last used socket?
def getSock(MAC):
    for sock in sockets:
        CMAC = eth_addr(sockets[sock])
        if CMAC == MAC :
            print("Match for " + MAC + " found: " + sock.getsockname()[0])
            return sock
    return None

# Receive a packet

# This is the IP address of the router.
IPTS = { "192.168.1.1" : socket1, "192.168.2.1" : socket2, "192.168.3.1" : socket3}
STIP = {v : k for k, v in IPTS.items()}

while True :
    while True:        
        packet = s.recvfrom(65565)
        packet = packet[0]

        #Parse ethernet header
        eth_length = 14
        eth_header = packet[:eth_length]
        eth_arr = unpack('!6s6sH' , eth_header)
        net_protocol = socket.ntohs(eth_arr[2])

        # OOP for the above parsing code
        eth = Ethernet()
        eth.dst = eth_arr[0]
        eth.src = eth_arr[1]
        eth.net_protocol = socket.ntohs(eth_arr[2])
        print("Received packet:")    
        print('Dest MAC : ' + eth_addr(eth.dst) + ' Src MAC : ' + eth_addr(eth.src) + ' Net Protocol : ' + str(eth.net_protocol))


        EPL = None
        IPL = None
        # Parse IP packets, IP Protocol number = 8
        if eth.net_protocol == 8:

            EPL = IP()

            # Take first 20 characters for the ip header
            ip_header = packet[eth_length:20 + eth_length]

            # Now unpack them
            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            version = version_ihl // 16
            ihl = version_ihl % 16

            iph_length = ihl * 4

            length = iph[2]
            ID = iph[3]
            frags = iph[4]
            ttl = iph[5]
            tr_protocol = iph[6]
            csum = iph[7]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])


            # Create IP packet payload
            EPL.version = version
            EPL.ihl = ihl
            EPL.frags = frags
            EPL.length = length
            EPL.ident = ID
            EPL.ttl = ttl
            EPL.protocol = tr_protocol
            EPL.csum = csum
            EPL.saddr = s_addr
            EPL.daddr = d_addr


            print ('IP Version : ' + str(EPL.version) + ' TTL : ' + str(ttl) + ' Tr Protocol : ' + str(tr_protocol))
            print ('IHL : ' + str(ihl) + ' FRAGS : ' + str(frags) + ' Identifier : ' + str(ID) + ' Checksum : ' + str(csum))
            print ('Src IP Address : ' + str(s_addr) + ' Dest IP Address : ' + str(d_addr))
            
            # TCP protocol
            if tr_protocol == 6 :
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]

                tcph = unpack('!HHLLBBHHH' , tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved // 16

                print ('Src Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Seq Number : ' + str(sequence) + ' Ack : ' + str(acknowledgement))

                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                # Get data from the packet
                data = packet[h_size:]

                # Fill IP payload
                IPL = TCP()
                IPL.sport = source_port
                IPL.dport = dest_port
                IPL.sequence = sequence
                IPL.ack = acknowledgement
                IPL.doff = tcph[4]
                IPL.flags = tcph[5]
                IPL.wind = tcph[6]
                IPL.csum = tcph[7]
                IPL.UP = tcph[8]
                
                IPL.data = data

                
            #ICMP Packets
            elif tr_protocol == 1 :
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]

                # Now unpack them :)
                icmph = unpack('!BBH' , icmp_header)

                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                print ('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))

                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size

                # Get data from the packet
                data = packet[h_size:]

                # Fill IP payload
                IPL = ICMP()
                IPL.type = icmp_type
                IPL.code = code
                IPL.csum = checksum
                IPL.data = data

            #UDP packets
            elif tr_protocol == 17 :
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]

                # Now unpack them :)
                udph = unpack('!HHHH' , udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                print('Src Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length))

                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size

                # Get data from the packet
                data = packet[h_size:]

                # Fill IP payload
                IPL = UDP()
                IPL.sport = source_port
                IPL.dport = dest_port
                IPL.length = length
                IPL.csum = checksum
                IPL.data = data



            # ERROR: Bad addresses
            # Checked after scanning to verify they were at least formatted correctly
            if eth_addr(eth_arr[0]) == eth_addr(eth_arr[1]) :
                print("ERROR A: Section 1")
                continue
            if eth_addr(eth_arr[1]) == eth_addr(eth_s1) or eth_addr(eth_arr[1]) == eth_addr(eth_s2) or eth_addr(eth_arr[1]) == eth_addr(eth_s3) :
                print("ERROR B : ATE OWN PACKET")
                continue


        # Start packet forwarding and error handling
        #0. check the ethernet payload is IP or Arp
        #    if it is Arp, update the arp table accordingly; goto step 5
        #    else if it is IP, goto step 1

        # Case: ARP
        if eth.net_protocol == 1544 :

            # IP header is ARP, unpack ARP
            EPL = ARP()
            arp_header = packet[eth_length:28+eth_length]
            arph = unpack('!HHBBH6s4s6s4s', arp_header)

            # Fill EPL ARP
            EPL.htype = arph[0]
            EPL.ptype = arph[1]
            EPL.hsize = arph[2]
            EPL.psize = arph[3]
            EPL.op = arph[4]
            EPL.shwa = arph[5]
            EPL.sipa = socket.inet_ntoa(arph[6])
            EPL.thwa = arph[7]
            EPL.tipa = socket.inet_ntoa(arph[8])

            # Print all
            print( "HTYPE : " + str(EPL.htype) + " PTYPE : " + str(EPL.ptype) + " HSIZE : " + str(EPL.hsize) + " PSIZE : " + str(EPL.psize) + " OP : " + str(EPL.op))
            print( "Source MAC : " + eth_addr(EPL.shwa) + " Source IP Address : " + str(EPL.sipa))
            print( "Dest MAC : " + eth_addr(EPL.thwa) + " Dest IP Address : " + str(EPL.tipa))

            # ERROR: Bad addresses
            # Checked after scanning to verify they were at least formatted correctly
            if eth_addr(eth_arr[0]) == eth_addr(eth_arr[1]) :
                print("ERROR A : Section 2")
                continue
            if eth_addr(eth_arr[1]) == eth_addr(eth_s1) or eth_addr(eth_arr[1]) == eth_addr(eth_s2) or eth_addr(eth_arr[1]) == eth_addr(eth_s3) :
                print("ERROR B : ATE OWN PACKET")
                continue
            # Update tables

            arp_table[EPL.sipa] = eth.src
            print(EPL.sipa + " : " + eth_addr(eth.src))
            # Get socket of receiver

            IIP = convertIP(EPL.sipa)
            sock = IPTS.get(EPL.tipa)
            print("Filling ip forwarding table...")
            for i in range(32):
                mask = IIP // (2**(31-i))
                ip_table[mask] = sock


            # CASE: ARP request and for existing port
            if(EPL.op == 1 and EPL.tipa in IPTS):
                arppack = ARP()
                arppack.htype = 1
                arppack.ptype = 2048
                arppack.hsize = 6
                arppack.psize = 4
                arppack.op = 2
                arppack.tipa = EPL.sipa
                arppack.sipa = STIP[sock]
                print("Replying to ARP sent by " + arppack.sipa)
                arppack.shwa = sockets[sock]
                arppack.thwa = EPL.shwa
                epack = Ethernet()
                epack.src = arppack.shwa
                epack.dst = arppack.thwa
                epack.net_protocol = 1544
                epack.payload = arppack
                packAndSend(epack, sock)

            break

        # Save payload to ethernet frame
        EPL.payload = IPL
        eth.payload = EPL

        # Adds known IP location

        IIP = convertIP(EPL.saddr)
        sock = getSock(eth_addr(eth.dst))
        
        for i in range(32):
            mask = IIP // (2**(31-i))
            ip_table[mask] = sock
            

        #1. decrement TTL by 1 in the ip header
        #    if TTL is 0, send back an ICMP error report (TTL exprire); goto step 5
        #    else overwrite the TTL in the ip header; goto step 2

        # Check TTL
        # CASE: TTL zero
        if(EPL.ttl == 1):
            # Respond with ICMP error report
            Report = ICMP()
            Report.type = 11
            Report.code = 1
            Report.csum = 0xD78E
            Report.data = None

            temp = EPL.saddr
            EPL.saddr = EPL.daddr
            EPL.daddr = temp
            
            # Fix checksum?
            EPL.csum = 0x10000 + (EPL.csum -EPL.ttl<<8) % 0x10000
            EPL.ttl = 255
            EPL.csum = (EPL.csum + 255<<8) % 0x10000
            
            EPL.payload = Report
            temp = eth.src
            eth.src = eth.dst
            eth.dst = temp
            
            packAndSend(eth, IPTS[EPL.saddr])
            break

        # CASE: Echo request for router
        if (isinstance(IPL, ICMP)) and IPL.type == 8 and EPL.daddr in IPTS:
            # Respond with ICMP echo reply
            Report = ICMP()
            Report.type = 0
            Report.code = 0
            Report.csum = 0xFFFF
            Report.data = None

            temp = EPL.saddr
            EPL.saddr = EPL.daddr
            EPL.daddr = temp
            
            # Fix checksum?
            EPL.csum = 0x10000 + (EPL.csum -EPL.ttl<<8) % 0x10000
            EPL.ttl = 255
            EPL.csum = (EPL.csum + 255<<8) % 0x10000
            
            EPL.payload = Report
            temp = eth.src
            eth.src = eth.dst
            eth.dst = temp
            
            packAndSend(eth, IPTS[EPL.saddr])
            break

        EPL.ttl = EPL.ttl-1
 

        #2. determine the outgoing socket by checking the IP forwarding table
        #    if no matching found in the IP forwardint table, send back an ICMP error report (net unreachable); goto step 5
        #    else goto step 3

        # Check IP forwarding table

        IPTF = convertIP(EPL.daddr)
        sock = None
        for i in range(32):
            mask = (IPTF //(2**(31-i)))
            if mask in ip_table:
                sock = ip_table[mask]

        

        # Case: must find IP by sending ARP and Ping
        if sock is None:
            # Send ICMP error report (T3C1)
            Report = ICMP()
            Report.type = 3
            Report.code = 1
            Report.csum = 0xFFFF - 3*2**8 - 1

            temp = EPL.saddr
            EPL.saddr = EPL.daddr
            EPL.daddr = temp
            # Fix checksum?
            EPL.csum = 0x10000 + (EPL.csum -EPL.ttl<<8) % 0x10000
            EPL.ttl = 255
            EPL.csum = (EPL.csum + 255<<8) % 0x10000
            
            EPL.payload = Report
            
            eframe = Ethernet()
            eframe.dst = arp_table[EPL.saddr]
            sock = getSock(arp_table[EPL.saddr])
            eframe.src = sockets[sock]
            eframe.net_protocol = 8
            eframe.payload = EPL
            packAndSend(eframe, sock)
            print("Sent ICMP Error")
            break
            
        
        
        #3. compute the new checksum and overwrite it in the ip header; goto step 4

        EPL.csum = (0x10000 + (EPL.csum - 0x100)) % 0x10000
        
        #4. determine the new dest mac addrres by checking the arp table
        #    if no matching found in the arp table, put the packet in the queue; goto step 5
        #    else overwrite the dest mac addrres and send the packet using the socket choosen in step 2; goto step 5

        # May as well be step five
        # Enqueue packet
        print("New packet added to queue")
        packet_queue.append(eth)
        break


    #5. for each packet in the queue (just try each packet once)
    #        if matching found in the arp table
    #           overwrite the dest mac addrres; determine the outgoing socket; send the packet; remove from the queue
    print("Scanning Queue...")
    while len(packet_queue) > 0:
            packet = packet_queue[i]
            DIP = packet.payload.daddr
            try:
                print("Requesting " + DIP)
                ERR = arp_table[DIP]
                # Get closest match

                IDIP = convertIP(DIP)
                sock = None
                for j in range(32):
                    mask = IDIP //(2** (31-j))
                    if mask in ip_table:
                        sock = ip_table[mask]
                print(sock.getsockname()[0])
                packet.src = sockets[sock]
                packet.dst = ERR
                print(eth_addr(packet.src) + " : " + eth_addr(packet.dst))
                packAndSend(packet, sock)
                print("Sent packet")
                del(packet_queue[0])
                continue

            except Exception:

                # Request ARP
                i = i + 1
                print("Sending ARP requests to...")
                arppack = ARP()
                arppack.htype = 1
                arppack.ptype = 2048
                arppack.hsize = 6
                arppack.psize = 4
                arppack.op = 1
                arppack.tipa = DIP
                for sock in sockets:
                    arppack.sipa = STIP[sock]
                    print(arppack.sipa)
                    arppack.shwa = sockets[sock]
                    arppack.thwa = "\0\0\0\0\0\0"
                    epack = Ethernet()
                    epack.src = arppack.shwa
                    epack.dst = eth_udest
                    epack.net_protocol = 1544
                    epack.payload = arppack
