from scapy.all import BitField, Packet

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

# SR==========================================================
class SourceRoute(Packet):
   fields_desc = [ BitField("nrouteid", 0, 112)]


MONITORING_DATA = {
  
}

# Functions===================================================
def handle_pkt(file, pkt):
  # print(pkt)
  # pkt.show2()

  if pkt[SourceRoute][IntHeader].remaining_hop_count != 0:     
    header_int_primeiro = pkt[SourceRoute][IntHeader]
    print(f"primeiro = {header_int_primeiro}")
  
  with open(file,'a+') as file:
    
    for i in range(pkt[SourceRoute][IntHeader].remaining_hop_count):
      
      header_int = header_int_primeiro[IntData][i]
      
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

      # file.write() -> This is not working yet 

      # print(f"switch = S{header_int.sw_id}")
      # for value in monitoring_data.values():
        # print(value, end=' ')
      # print('\n')

if __name__ == '__main__':
   pass
