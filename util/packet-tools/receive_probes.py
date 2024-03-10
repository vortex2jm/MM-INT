#!/usr/bin python3
from lib.Int import SourceRoute, IntHeader, IntData, IntTools
from scapy.all import bind_layers, Ether, IP, sniff
from lib.influx import DataBase
from dotenv import load_dotenv
import sys
import os

load_dotenv()

TOKEN=os.getenv('TOKEN')
ORG='MM-Int'
BUCKET='solution-3'

def main():
  if len(sys.argv) < 3:
    print("Usage: python receive.py <core switch connected interface> <file name> (ex:e2-eth1 test-file)")
    sys.exit(1)
  
  iface = sys.argv[1]
  file = f'logs/log_INT_{sys.argv[2]}.txt'

  bind_layers(Ether, SourceRoute)
  bind_layers(SourceRoute, IntHeader)
  bind_layers(IntHeader,IntData)
  bind_layers(IntData, IntData)
  bind_layers(IntData, IP) 
  
  print("Waiting packets...")

  db = DataBase(TOKEN, ORG, BUCKET) #This parameter will be inserted on handle_packet
  IntTools.create_logfile(file)  # Creates file for logs
  sniff(iface = iface, prn = lambda x: IntTools.handle_pkt(x, file, db), filter = "ether proto 0x2020")

# Running=================
if __name__ == '__main__':
    main()
