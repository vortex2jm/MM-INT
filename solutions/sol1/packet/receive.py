#!/usr/bin python3

import argparse
import sys
import socket
import random
import struct
import os

from time import sleep
from scapy.all import Packet, bind_layers, XByteField, FieldLenField, BitField, ShortField, IntField, PacketListField, Ether, IP, UDP, sendp, get_if_hwaddr, sniff, ICMP


class IntHeader(Packet):
    fields_desc = [ BitField("ver", 0, 4),
                    BitField("d", 0, 1),
                    BitField("e", 0, 1),
                    BitField("m", 0, 1),
                    BitField("r", 0, 12),
                    BitField("hop_ml", 0, 5),
                    BitField("remaining_hop_count", 0, 8),
                    BitField("instruction_bitmap", 0, 16),
                    BitField("domain_specific_id", 0, 16),
                    BitField("domain_instruction", 0, 16),
                    BitField("ds_flags", 0, 16)]

class IntData(Packet):
    fields_desc = [ BitField("sw_id", 0, 32),
                    BitField("ingress_port", 0, 32),
                    BitField("egress_port", 0, 32),
                    BitField("replicate_count", 0, 32),
                    BitField("ingress_global_timestamp", 0, 64),
                    BitField("egress_global_timestamp", 0, 64),
                    BitField("enq_timestamp", 0, 32),
                    #BitField("enq_qdepth", 0, 32),
                    BitField("deq_timedelta", 0, 32),
                    BitField("deq_qdepth", 0, 32),
                    BitField("port1_enq_qdepth0", 0, 32),
                    BitField("port1_enq_qdepth1", 0, 32),
                    BitField("port2_enq_qdepth0", 0, 32),
                    BitField("port2_enq_qdepth1", 0, 32),
                    BitField("port3_enq_qdepth0", 0, 32),
                    BitField("port3_enq_qdepth1", 0, 32),
                    BitField("port4_enq_qdepth0", 0, 32),
                    BitField("port4_enq_qdepth1", 0, 32),
                    BitField("priority", 0, 3),
                    BitField("qid", 0, 5)]


class SourceRoute(Packet):
   fields_desc = [ BitField("nrouteid", 0, 112)]


def logInt(arquivo, fields_value_line):
  with open(arquivo,'a+') as file:
     file.write(fields_value_line)


def handle_pkt(arquivo, pkt):
  print(pkt)
  pkt.show2()

  if pkt[SourceRoute][IntHeader].remaining_hop_count != 0:     
    header_int_primeiro = pkt[SourceRoute][IntHeader]
    print(f"primeiro = {header_int_primeiro}")
  for i in range(pkt[SourceRoute][IntHeader].remaining_hop_count):
    header_int = header_int_primeiro[IntData][i]
    id_switch_atual = header_int.sw_id
    print(f"switch = S{id_switch_atual}")
  
    fields_value_line = f'{header_int.sw_id}, {header_int.port1_enq_qdepth0}, {header_int.port1_enq_qdepth1}, {header_int.port2_enq_qdepth0}, {header_int.port2_enq_qdepth1}, {header_int.port3_enq_qdepth0}, {header_int.port3_enq_qdepth1}, {header_int.port4_enq_qdepth0}, {header_int.port4_enq_qdepth1}\n'
    print(fields_value_line)
    logInt(arquivo, fields_value_line)


def main():
  if len(sys.argv) < 3:
        print("Uso: python receive_atualizado.py interface switchCore (ex:e2-eth1 E2, sendo E2 nome de arquivo de log que vao ser armazenados os dados)")
        sys.exit(1)
  iface = sys.argv[1]
  switch_log = sys.argv[2]

  arquivo = f'logs/log_INT_{switch_log}.txt'
  header_fileLog = ['switchID_t', 'port1_enq_qdepth0', 'port1_enq_qdepth1', 
                    'port2_enq_qdepth0', 'port2_enq_qdepth1', 
                    'port3_enq_qdepth0', 'port3_enq_qdepth1', 
                    'port4_enq_qdepth0', 'port4_enq_qdepth1' ]
  header_fileLogAux = [f'{item}' for item in header_fileLog]
  header = ", ".join(header_fileLogAux)
  
  with open(arquivo, 'w') as file:
    # Escreve o cabeçalho no início do arquivo
    file.write(str(header) + '\n')
  bind_layers(Ether, SourceRoute)
  bind_layers(SourceRoute, IntHeader)
  bind_layers(IntHeader,IntData)
  bind_layers(IntData, IntData)
  bind_layers(IntData, IP) #nao funcionando
  #bind_layers(IP, nodeCount, proto = 8224)
  print("Aguardando pacotes")
  sniff(iface = iface, prn = lambda x: handle_pkt(arquivo, x), filter = "ether proto 0x2020")

if __name__ == '__main__':
    main()
