#!/usr/bin python3
from lib.Int import SourceRoute, IntHeader, IntDataS3, IntDataS1, IntTools
from scapy.all import bind_layers, Ether, IP, sniff
from lib.influx import DataBase
from dotenv import load_dotenv
import argparse
import os

# env
load_dotenv()

TOKEN=os.getenv('TOKEN')
ORG='MM-Int'
BUCKET='solution-3'

# arguments========================
parser = argparse.ArgumentParser(description='===INT PROBES COLLECTOR===')
parser.add_argument('-s', '--solution', type=int, action='store', help='Chosen routing solution (default:3)', default=3)
parser.add_argument('-i', '--interface', type=str, action='store', help='Interface connected to core switch (ex:e2-eth1)', required=True)
parser.add_argument('-db', '--database', action='store_true', help='Write data in database')
parser.add_argument('-f', '--file', type=str, action='store', help='Log file name', default=None)
args = parser.parse_args()

def main():
  iface = args.interface
  IntTools.solution = args.solution

  if args.solution == 1:
    bind_layers(Ether, IntHeader)
    bind_layers(IntHeader,IntDataS1)
    bind_layers(IntDataS1, IntDataS1)
    bind_layers(IntDataS1, IP)
    callback = IntTools.handle_pkt_s1
  
  if args.solution == 3: 
    bind_layers(Ether, SourceRoute)
    bind_layers(SourceRoute, IntHeader)
    bind_layers(IntHeader,IntDataS3)
    bind_layers(IntDataS3, IntDataS3)
    bind_layers(IntDataS3, IP)
    callback = IntTools.handle_pkt_s3 # Assigning function
  
  print("Waiting packets...")

  db = None

  if args.database: 
    db = DataBase(TOKEN, ORG, BUCKET)
  
  if args.file:
    file = f'logs/log_INT_{args.file}.txt'
    IntTools.create_logfile(file)

  print('ALOUUUUU')

  sniff(iface = iface, prn = lambda x: callback(x, file, db), filter = "ether proto 0x2020")

# Running=================
if __name__ == '__main__':
    main()
