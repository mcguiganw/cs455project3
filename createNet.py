#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
    def terminate( self ):
        super( LinuxRouter, self ).terminate()        

class NetworkTopo( Topo ):
    "A LinuxRouter connecting three IP subnets"

    def build( self, **_opts ):

        # One router
        r0 = self.addNode( 'r0', cls=LinuxRouter, ip='192.168.1.1/24' )

        # Three switches
        s1, s2, s3 = [ self.addSwitch( s ) for s in 's1', 's2', 's3' ]

        self.addLink( s1, r0, intfName2='r0-eth1',
                      params2={ 'ip' : '192.168.1.1/24' } )
        self.addLink( s2, r0, intfName2='r0-eth2',
                      params2={ 'ip' : '192.168.2.1/24' } )
        self.addLink( s3, r0, intfName2='r0-eth3',
                      params2={ 'ip' : '192.168.3.1/24' } )

        # Six hosts
        h11 = self.addHost( 'h11', ip='192.168.1.100/24',mac='00:00:00:00:11:00',
                           defaultRoute='via 192.168.1.1' )
        h12 = self.addHost( 'h12', ip='192.168.1.101/24',mac='00:00:00:00:12:00',
                           defaultRoute='via 192.168.1.1' )
        h21 = self.addHost( 'h21', ip='192.168.2.100/24',mac='00:00:00:00:21:00',
                           defaultRoute='via 192.168.2.1' )
        h22 = self.addHost( 'h22', ip='192.168.2.101/24',mac='00:00:00:00:22:00',
                           defaultRoute='via 192.168.2.1' )
        h31 = self.addHost( 'h31', ip='192.168.3.100/24',mac='00:00:00:00:31:00',
                           defaultRoute='via 192.168.3.1' )
        h32 = self.addHost( 'h32', ip='192.168.3.101/24',mac='00:00:00:00:32:00',
                           defaultRoute='via 192.168.3.1' )
        
        # Links  
        for h, s in [ (h11, s1), (h12, s1), (h21, s2), (h22, s2), (h31, s3), (h32, s3) ]:
            self.addLink( h, s )

def run():
    "Test linux router"
    topo = NetworkTopo()
    net = Mininet( topo=topo )  # controller is used by s1-s3
    net.start()
    r0 = net.get( 'r0' )
    r0.intf('r0-eth1').setMAC('00:00:00:00:00:01')
    r0.intf('r0-eth2').setMAC('00:00:00:00:00:02')
    r0.intf('r0-eth3').setMAC('00:00:00:00:00:03')
    r0.cmd('echo "1" >  /proc/sys/net/ipv4/icmp_echo_ignore_all')    
    info( '*** Routing Table on Router:\n' )
    print net[ 'r0' ].cmd( 'route' )
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
