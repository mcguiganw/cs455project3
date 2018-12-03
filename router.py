import socket, sys
from struct import *
from Queue import Queue

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

# Create a AF_PACKET type raw socket
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

eth_s1 = chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x01)
eth_s2 = chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x02)
eth_s3 = chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x00) + chr(0x03)

socket1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
socket1.bind(("r0-eth1", 0))
socket2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
socket2.bind(("r0-eth2", 0))
socket3 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
socket3.bind(("r0-eth3", 0))

# IP Forward table
ip_table = []

# Arp table
arp_table = []

# Buffer queue
packet_queue = Queue()


# It is better to do this project using OOP, defining a class for each layer
class Ethernet(object) :
    def __init__(self) :
        self.dst = None
        self.src = None
        self.net_protocol = None
        self.payload = None

class Arp(object) :
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

# You may define IP, TCP, UDP, ICMP like above

# Receive a packet
while True :
    packet = s.recvfrom(65565)
    packet = packet[0]

    # Parse ethernet header
    eth_length = 14
    eth_header = packet[:eth_length]
    eth_arr = unpack('!6s6sH' , eth_header)
    net_protocol = socket.ntohs(eth_arr[2])
    if eth_addr(eth_arr[0]) == eth_addr(eth_arr[1]) :
        continue
    if eth_addr(eth_arr[1]) == eth_addr(eth_s1) or eth_addr(eth_arr[1]) == eth_addr(eth_s2) or eth_addr(eth_arr[1]) == eth_addr(eth_s3) :
        continue
    print "Received packet:"
    print 'Dest MAC : ' + eth_addr(eth_arr[0]) + ' Src MAC : ' + eth_addr(eth_arr[1]) + ' Net Protocol : ' + str(net_protocol)
    
    # Parse IP packets, IP Protocol number = 8
    if socket.ntohs(eth_arr[2]) == 8 :

        # Take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # Now unpack them
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        tr_protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print 'IP Version : ' + str(version) + ' TTL : ' + str(ttl) + ' Tr Protocol : ' + str(tr_protocol)
        print 'Src IP Address : ' + str(s_addr) + ' Dest IP Address : ' + str(d_addr)
        
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
            tcph_length = doff_reserved >> 4

            print 'Src Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Seq Number : ' + str(sequence) + ' Ack : ' + str(acknowledgement)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            # Get data from the packet
            data = packet[h_size:]

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

            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            # Get data from the packet
            data = packet[h_size:]


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

            print 'Src Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length)

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            # Get data from the packet
            data = packet[h_size:]


    # Start packet forwarding and error handling
   '''
    #Error report
    def ICMP(check):
        if check == 1:
            #TTL EXPIRED
        else :
            #net unreachable
    #Step 0 find type
    def checkType():
        if type == arp :
            updateTable()
            sendPacket()
        else :
            decTTL()
    #Step 1 decriment TTL   
    def decTTL():
        if ttl == 0:
            ICMP(0)
        else :
            ttl = ttl-1
            findSocket()
    #Step 2 find outgoing socket      
    def findSocket():
       found = false
       for i in  ip_table:
            if i == destSocket :
                found = true
                computeCheckSum()
       if found == true :
            findMAC()
       else :
            ICMP(1)
            sendPacket()
    #Step 3 compute checkSum
    def computeCheckSum():
        checksum = placeholder # new checksum
        iph = checksum
    #Step 4 determine dest MAC address
    def findMAC() :
        found = false
        for i in arp_table :
            if i == macAddress:
                found == true
        if found != true
            destMAC = newMAC
        sendPacket() 
     def sendPacket() :        
            send(packet)
    '''
  # OOP for the above parsing code
    '''
    eth = Ethernet()
    eth.dst = eth_arr[0]
    eth.src = eth_arr[1]
    eth.net_protocol = socket.ntohs(eth_arr[2])
    print "Received packet:"    
    print 'Dest MAC : ' + eth_addr(eth.dst) + ' Src MAC : ' + eth_addr(eth.src) + ' Net Protocol : ' + str(eth.net_protocol)
    0. check the ethernet payload is IP or Arp
        if it is Arp, update the arp table accordingly; goto step 5
        else if it is IP, goto step 1
    1. decrement TTL by 1 in the ip header
        if TTL is 0, send back an ICMP error report (TTL exprire); goto step 5
        else overwrite the TTL in the ip header; goto step 2
    2. determine the outgoing socket by checking the IP forwarding table
        if no matching found in the IP forwardint table, send back an ICMP error report (net unreachable); goto step 5
        else goto step 3
    3. compute the new checksum and overwrite it in the ip header; goto step 4
    4. determine the new dest mac addrres by checking the arp table
        if no matching found in the arp table, put the packet in the queue; goto step 5
        else overwrite the dest mac addrres and send the packet using the socket choosen in step 2; goto step 5
    5. for each packet in the queue (just try each packet once)
            if matching found in the arp table
                overwrite the dest mac addrres; determine the outgoing socket; send the packet; remove from the queue
    '''
