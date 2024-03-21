#!/usr/bin/env python
import sys
import time
import random
from scapy.all import *

def main():
    if len(sys.argv) < 2:
        print("Uso: python send.py ipDest (ex: python3 send.py 10.0.1.2)")
        sys.exit(1)

    ip_dst = sys.argv[1]
    identification=random.randint(1,65535)

    pkt = Ether(dst='00:04:00:00:00:01', src=get_if_hwaddr('eth0'), type=0x800);   #2048 works
    pkt = pkt/IP(id=identification, src= get_if_addr('eth0'), dst=ip_dst, tos = 55)/UDP(dport=1234, sport=random.randint(49152,65535))   #adicionando um header de udp para evitar resposta ICMP
    
    try:
        while(True):
            pkt.show2()
            sendp(pkt, iface='eth0')
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit()

if __name__ == '__main__':
    main()
