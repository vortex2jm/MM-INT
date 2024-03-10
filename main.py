from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from time import sleep
from util.topo.topology import INTTopo
from util.topo.p4_mininet import P4Host, P4Switch
import argparse
import os


# Catching arguments========================================
parser = argparse.ArgumentParser(description='Mininet demo')

parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", default="simple_switch")

parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)

#parser.add_argument('--json', help='Path to JSON config file',
#                    type=str, action="store", required=False)

parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)

args = parser.parse_args()


#==========================================================
def main():
    num_hosts = 8

    topo = INTTopo(args.behavioral_exe,
                   #args.json,
                   args.thrift_port,
                   args.pcap_dump,
                   num_hosts)
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
                  controller = None)
    net.start()
    net.staticArp()

    os.system("./solutions/sol3/flow_table/f.sh")

    for n in range(num_hosts):
        h = net.get('h%d' % (n + 1))
        h.describe()
        if n != 0:
            h.cmd("ethtool --offload eth0 rx off tx off")
            h.cmd("python2 ../packet/receive.py >/dev/null &")
            h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
            h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
            h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
            h.cmd("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP") 

    for sw in net.switches:
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    sleep(1)

    print("Ready !")

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()
