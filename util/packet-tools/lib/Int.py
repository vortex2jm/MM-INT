from scapy.all import BitField, Packet
from lib.influx import DataBase
import sys

# Header===================================================
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

# Data=====================================================
class IntDataS3(Packet):
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

class IntDataS1(Packet):
  fields_desc = [ BitField("sw_id", 0, 32),
                  BitField("ingress_port", 0, 32),
                  BitField("egress_port", 0, 32),
                  BitField("replicate_count", 0, 32),
                  BitField("ingress_global_timestamp", 0, 64),
                  BitField("egress_global_timestamp", 0, 64),
                  BitField("enq_timestamp", 0, 32),
                  BitField("enq_qdepth", 0, 32), #solucao 1
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

# SR==========================================================
class SourceRoute(Packet):
   fields_desc = [ BitField("nrouteid", 0, 112)]


# Global======================================================
HEADER_LOGFILE_S3 = ['switchID_t', 'port1_enq_qdepth0', 'port1_enq_qdepth1', 
                    'port2_enq_qdepth0', 'port2_enq_qdepth1', 
                    'port3_enq_qdepth0', 'port3_enq_qdepth1', 
                    'port4_enq_qdepth0', 'port4_enq_qdepth1' ]

HEADER_LOGFILE_S1 = ['switchID_t', 'egress_port', 'qid', 'enq_qdepth']

# Tools===================================================
class IntTools:

  solution = 0

  #=============================================================
  @classmethod
  def create_logfile(cls, file):
    if cls.solution == 3:
      header_fileLogAux = [f'{item}' for item in HEADER_LOGFILE_S3]
    elif cls.solution == 1:
      header_fileLogAux = [f'{item}' for item in HEADER_LOGFILE_S1]
    else:
      print('Something went wrong')
      sys.exit(1)
    
    header = ", ".join(header_fileLogAux)
    # Writes the file header
    with open(file, 'w') as log_file:
      log_file.write(str(header) + '\n')


  #=============================================================
  @staticmethod
  def handle_pkt_s3(pkt ,file=None, db=None):
    # Methods to show packet details
    # print(pkt)
    # pkt.show2()

    if pkt[SourceRoute][IntHeader].remaining_hop_count != 0:     
      header_int_first = pkt[SourceRoute][IntHeader]
      print(f"FIRST = {header_int_first}")

    # Verifying if file path paparameter is not the default==========
    log_file = None
    if file:
      log_file = open(file, 'a+')

    for i in range(pkt[SourceRoute][IntHeader].remaining_hop_count):
      header_int = header_int_first[IntDataS3][i]
      monitoring_data = {
        'swid':header_int.sw_id,
        'p1q0':header_int.port1_enq_qdepth0,
        'p1q1':header_int.port1_enq_qdepth1,
        'p2q0':header_int.port2_enq_qdepth0,
        'p2q1':header_int.port2_enq_qdepth1,
        'p3q0':header_int.port3_enq_qdepth0,
        'p3q1':header_int.port3_enq_qdepth1,
        'p4q0':header_int.port4_enq_qdepth0,
        'p4q1':header_int.port4_enq_qdepth1 
      }

      # Printing output=====================
      print(f"switch = S{header_int.sw_id}")
      for value in monitoring_data.values():
        print(value, end=' ')
        if log_file:
          log_file.write(f'{value} ')
      print('\n')
      if log_file:
        log_file.write('\n') 

      # Verifying if there's a database============
      if db == None:
        print('No database available')
        continue
      
      #Inserting data on DB========================
      points = DataBase.parse_packet(monitoring_data)
      db.write_data(points)

    # Writing finished
    if log_file:
      log_file.close()                


  #=======================================================
  @staticmethod
  def handle_pkt_s1(pkt ,file=None, db=None):

    if pkt[IntHeader].remaining_hop_count != 0:   
      header_int_first = pkt[IntHeader]
      print(f"FIRST = {header_int_first}")    
    
    log_file = None
    if file:
      log_file = open(file, 'a+')

    for i in range(pkt[IntHeader].remaining_hop_count): #solucao1
      header_int = header_int_first[IntDataS1][i]
      monitoring_data = {
        'sw_id': header_int.sw_id,
        'egress_port': header_int.egress_port,
        'qid': header_int.qid,
        'enq_depth': header_int.enq_qdepth
      }
      
      # Printing output=====================
      print(f"switch = S{header_int.sw_id}")
      for value in monitoring_data.values():
        print(value, end=' ')
        if log_file:
          log_file.write(f'{value} ')
      print('\n')
      if log_file:
        log_file.write('\n') 

      # Verifying if there's a database============
      if db == None:
        print('No database available')
        continue
      
      #Inserting data on DB========================
      points = DataBase.parse_packet(monitoring_data)
      db.write_data(points)

    # Writing finished
    if log_file:
      log_file.close() 


if __name__ == '__main__':
   pass
