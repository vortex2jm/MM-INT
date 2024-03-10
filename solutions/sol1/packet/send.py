#!/usr/bin/env python
import sys
import time
import random
from scapy.all import *

def main():
    #pra rodar: 
        #mandar por parametro o destino (ex: 10.0.1.2 para switch 2)
        #mandar como segundo parametro sport do UDP (44444 para fila 0 e 4445 para fila 1)

    if len(sys.argv) < 2:
        print("Uso: python send.py ipDestino")
        sys.exit(1)

    identification=random.randint(1,65535)
    #print(f"0 = {sys.argv[0]}")
    #print(f"1 ={sys.argv[1]}")
    #print(f"2 = {sys.argv[2]}")

    var_ip_dst = sys.argv[1]
    #var_sport = int(sys.argv[2])

    # iface = 'h0-eth0'

    # pkt =  Ether(dst='00:aa:bb:00:00:00', src=get_if_hwaddr('eth0'), type=8224);
    
    pkt =  Ether(dst='00:04:00:00:00:01', src=get_if_hwaddr('eth0'), type=0x800);   #2048 works

    # try:
    #     pkt = pkt / SourceRoute(nrouteid=1915945086214166489341648836749912) #borda so faz essa linha - alem do routeID, inserir o cabecalho INT
    # except ValueError:
    #     pass

    # pkt = pkt / IP(id=identification)/IntHeader(ver=2, d=0, e=0, m=0, r=0, hop_ml=10, remaining_hop_count=0, instruction_bitmap=56832, domain_specific_id=0x0000)

    pkt = pkt/IP(id=identification, src= get_if_addr('eth0'), dst='10.0.1.2', tos = 55)/UDP(dport=1234, sport=random.randint(49152,65535))   #adicionando um header de udp para evitar resposta ICMP
    #pkt = pkt/IP(id=identification, src= get_if_addr('eth0'), dst=var_ip_dst, tos = 55)/UDP(dport=1234, sport=var_sport)
    try:
        #while(True):
        pkt.show2()
        sendp(pkt, iface='eth0')
        time.sleep(1)
        #time.sleep(1)
    except KeyboardInterrupt:
        sys.exit()

if __name__ == '__main__':
    main()
