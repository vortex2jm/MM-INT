#!/usr/bin python3
import sys
from scapy.all import bind_layers, Ether, IP, sniff
from lib.Int import SourceRoute, IntHeader, IntData, handle_pkt

HEADER_LOGFILE = ['switchID_t', 'port1_enq_qdepth0', 'port1_enq_qdepth1', 
                    'port2_enq_qdepth0', 'port2_enq_qdepth1', 
                    'port3_enq_qdepth0', 'port3_enq_qdepth1', 
                    'port4_enq_qdepth0', 'port4_enq_qdepth1' ]

def main():
  # Args verification===========
  if len(sys.argv) < 3:
        print("Usage: python receive.py <core switch connected interface> <file name> (ex:e2-eth1 test-file)")
        sys.exit(1)
  iface = sys.argv[1]
  switch_log = sys.argv[2]

  file = f'logs/log_INT_{switch_log}.txt'
  
  header_fileLogAux = [f'{item}' for item in HEADER_LOGFILE]
  header = ", ".join(header_fileLogAux)
  
  with open(file, 'w') as file:
    # Escreve o cabeçalho no início do arquivo
    file.write(str(header) + '\n')

  bind_layers(Ether, SourceRoute)
  bind_layers(SourceRoute, IntHeader)
  bind_layers(IntHeader,IntData)
  bind_layers(IntData, IntData)
  bind_layers(IntData, IP) 
  
  print("Waiting packets...")
  sniff(iface = iface, prn = lambda x: handle_pkt(file, x), filter = "ether proto 0x2020")

# Running=================
if __name__ == '__main__':
    main()
