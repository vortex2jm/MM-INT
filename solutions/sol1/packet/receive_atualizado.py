#!/usr/bin python3

import argparse
import sys
import socket
import random
import struct

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
                    BitField("enq_qdepth", 0, 32), #solucao1
                    BitField("deq_timedelta", 0, 32),
                    BitField("deq_qdepth", 0, 32),
                    # BitField("port1_enq_qdepth0", 0, 32),
                    # BitField("port1_enq_qdepth1", 0, 32),
                    # BitField("port2_enq_qdepth0", 0, 32),
                    # BitField("port2_enq_qdepth1", 0, 32),
                    # BitField("port3_enq_qdepth0", 0, 32),
                    # BitField("port3_enq_qdepth1", 0, 32),
                    # BitField("port4_enq_qdepth0", 0, 32),
                    # BitField("port4_enq_qdepth1", 0, 32),
                    BitField("priority", 0, 3),
                    BitField("qid", 0, 5)]


#class SourceRoute(Packet):
  #  fields_desc = [ BitField("nrouteid", 0, 112)]



#class InBandNetworkTelemetry(Packet):
#    fields_desc = [ BitField("switchID_t", 0, 8),
#                    BitField("priority", 0, 3),
#                    BitField("qid", 0, 5),
#                    BitField("enq_qdepth0", 0, 32),
#                    BitField("enq_qdepth1", 0, 32),
#                    BitField("totalLen",0,16)
#                  ]
#    """any thing after this packet is extracted is padding"""
#    def extract_padding(self, p):
#                return "", p

#class nodeCount(Packet):
  #name = "nodeCount"
  #fields_desc = [ ShortField("count", 0), ShortField("priority", 0),
#                  PacketListField("INT", [], InBandNetworkTelemetry, count_from=lambda pkt:(pkt.count*1))]


def getFields(pkt):
  fields_names = []
  fields = {}
  print("teste")
  #print(pkt)
  #pkt.show2()
  #=for lengthInt in range(len(pkt[nodeCount].INT)):
    #field_names = [field.name for field in pkt[nodeCount].INT[lengthInt].fields_desc]
    #fields[lengthInt] = {field_name: getattr(pkt[nodeCount].INT[lengthInt], field_name) for field_name in field_names}
  #print('fields retornado = ' + str(fields))
  return fields

def handle_pkt(pkt):
  fields_value = getFields(pkt)
  #int_header_layer = pkt[SourceRoute][IntHeader]
  #print(int_header_layer.remaining_hop_count)
  print("teste")
  print(fields_value)
  #logInt(fields_value)


  pkt.show2()

def main():
  #new, output file
  #header_fileLog = ['switchID_t', 'priority', 'qid', 'enq_qdepth0', 'enq_qdepth1', 'totalLen', 'switchID_t', 'priority', 'qid', 'enq_qdepth0', 'enq_qdepth1', 'totalLen']
  #header_fileLogAux = [f'{item}' for item in header_fileLog]
  #header = ", ".join(header_fileLogAux)
  #print(header)

  #with open('logs/log_INT.txt','w+') as file:
      #file.write(str(header) + '\n')
  #mudei
  #iface = 'enp0s8'
  if len(sys.argv) < 2:
        print("Uso: python receive_atualizado.py interface (ex:e2-eth1)")
        sys.exit(1)
  iface = sys.argv[1]
  # bind_layers(Ether, IP, type = 0x2020)
  # bind_layers(IP, ICMP, proto = 1)
  # bind_layers(ICMP, SourceRoute)
  # bind_layers(SourceRoute, IntHeader, code = 118)
  # bind_layers(IntHeader, IntData)
  # bind_layers(IntData, IntData)
                                  # bind_layers(Ether, SourceRoute) solucao3
                                  # bind_layers(SourceRoute, IntHeader)
                                  # bind_layers(IntHeader,IntData)
                                  # bind_layers(IntData, IntData)
                                  # bind_layers(IntData, IP)

  bind_layers(Ether, IntHeader)
  bind_layers(IntHeader,IntData)
  bind_layers(IntData, IntData)
  bind_layers(IntData, IP)
  #bind_layers(IP, nodeCount, proto = 8224)
  print("oi")
  sniff(iface = iface, prn = lambda x: handle_pkt(x), filter = "ether proto 0x2020")
  #sniff(filter = "ip proto 253", iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
