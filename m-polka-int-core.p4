/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** C O N S T A N T S ********************************
*************************************************************************/
#define MAX_HOPS 20

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x2020;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<3> priority_v;
typedef bit<5> qid_v;
typedef bit<32> enq_qdepth_v;

enum bit<8> FieldLists {
    resubmit_fl1 = 0
}

struct mymeta_t {
    @field_list(FieldLists.resubmit_fl1)
    bit<3>   resubmit_reason;
    @field_list(FieldLists.resubmit_fl1)
    bit<9> f1;
}

header ethernet_t {
  macAddr_t dstAddr;
  macAddr_t srcAddr;
  bit<16>   etherType;
}

header srcRoute_t {
  //bit<160>   routeId;
  bit<112>   routeId; //7 nos
}

header ipv4_t {
  bit<4>  version;
  bit<4>  ihl;
  bit<8>  diffserv;
  bit<16> totalLen;
  bit<16> identification;
  bit<3>  flags;
  bit<13> fragOffset;
  bit<8>  ttl;
  bit<8>  protocol;
  bit<16> hdrChecksum;
  bit<32> srcAddr;
  bit<32> dstAddr;
}

struct polka_t_top {
  macAddr_t dstAddr;
  macAddr_t srcAddr;
  bit<16>   etherType;
  bit<160>   routeId;
}


header intoption_t {
bit<4>    ver;
bit<1>    d;
bit<1>    e;
bit<1>    m;
bit<12>   r;
bit<5>    hop_ml;
bit<8>    remaining_hop_count; //int_total_num
bit<16>   instruction_bitmap;
bit<16>   domain_specific_id;
bit<16>   domain_instruction;
bit<16>   ds_flags;
}

header inthdr_t {
  bit<32>    sw_id;
  bit<32>    ingress_port;
  bit<32>    egress_port;
  bit<32>    replicate_count;
  bit<64>   ingress_global_timestamp;
  bit<64>   egress_global_timestamp;
  bit<32>   enq_timestamp;
  bit<32>   deq_timedelta;
  bit<32>   deq_qdepth;
  //cada switch q passar capta todas as infos dela (as 2 filas de cada porta)
  enq_qdepth_v port1_enq_qdepth0;
  enq_qdepth_v port1_enq_qdepth1;

  enq_qdepth_v port2_enq_qdepth0;
  enq_qdepth_v port2_enq_qdepth1;

  enq_qdepth_v port3_enq_qdepth0;
  enq_qdepth_v port3_enq_qdepth1;

  enq_qdepth_v port4_enq_qdepth0;
  enq_qdepth_v port4_enq_qdepth1;
  //apenas para visualizacao de mudanca:
  priority_v priority;
  qid_v      qid;
}


header last_egress_sampling_timestamp_t {
  bit<48>   h_last_egress_sampling_timestamp;
}

struct metadata {
  bit<112>  routeId;
  bit<16>   etherType;
  bit<1>    apply_sr;
  bit<1>    apply_decap;
  bit<9>    port;
  bit<9>    f_port;
  bit<9>    count;
  bit<8>    n_bits;
  bit<9>    egress_int;

  bit<8> int_info_remaining;
  bit<8> path_info_remaining;
  last_egress_sampling_timestamp_t m_last_egress_sampling_timestamp;

  mymeta_t mymeta;
}

struct headers {
  ethernet_t          ethernet;
  srcRoute_t          srcRoute;
  //ipv4_t              ipv4;
  intoption_t         int_option;
  inthdr_t[MAX_HOPS]  int_info;
  ipv4_t              ipv4;
}

//register<bit<48>>(960) r_last_egress_global_timestamp;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

  state start {
    meta.apply_sr = 0;
    meta.egress_int = 0;
    transition parse_ethernet;
  }

  state parse_ethernet {
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
      TYPE_SRCROUTING: get_routeId;
      TYPE_IPV4: parse_ipv4;
      default: accept;
    }
  }

  state get_routeId {
    meta.apply_sr = 1;
    packet.extract(hdr.srcRoute);
    meta.routeId = hdr.srcRoute.routeId;
    transition parse_int_option;
  }

  state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition accept;
  }

  state parse_int_option {
    packet.extract(hdr.int_option);
    meta.int_info_remaining = hdr.int_option.remaining_hop_count;
    transition select(meta.int_info_remaining) {
      0 : parse_ipv4;
      default: parse_int_info;
    }
  }

  //a partir do segundo pacote
  state parse_int_info {
    packet.extract(hdr.int_info.next);
    meta.int_info_remaining = meta.int_info_remaining - 1;
    transition select(meta.int_info_remaining) {
      0 : parse_ipv4;
      default: parse_int_info;
    }
  }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

  action drop() {
    mark_to_drop(standard_metadata);
  }

  action clone_packet(bit<32> mirror_session_id) {
    // Clone from ingress to egress pipeline
    clone(CloneType.I2E, mirror_session_id);
  }

  action do_resubmit_reason1() {
        meta.mymeta.resubmit_reason = 1;
        meta.mymeta.f1 = meta.f_port;
        resubmit_preserving_field_list((bit<8>)FieldLists.resubmit_fl1);
  }

  action srcRoute_nhop() {

    bit<16> nbase=0;
    bit<64> ncount=4294967296*2;
    bit<16> nresult;
    bit<16> nport;

    bit<112>routeid = meta.routeId;

    bit<112>ndata = routeid >> 16;
    bit<16> dif = (bit<16>) (routeid ^ (ndata << 16));

    hash(
      nresult,
      HashAlgorithm.crc16_custom,
      nbase,
      {ndata},ncount
    );

    nport = nresult ^ dif;

    meta.port = (bit<9>) nport;

  }

  action ipv4_forward(egressSpec_t port) {
    standard_metadata.egress_spec = port;

    hdr.ipv4.ttl = hdr.ipv4.ttl -1;
  }

  action  ip_sender_change_priority(bit<3> new_priority){
    standard_metadata.priority = new_priority;
  }

  table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
  }

    table ip_sender_match_table{
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            ip_sender_change_priority;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

  apply {
    if (meta.apply_sr==1){
      standard_metadata.priority = 1; //passando pelas filas 0 (define qid = 0 na saida) - tanto faz vai ler de todos
      if (meta.mymeta.resubmit_reason == 0) {
            // Source-routing calculation
            srcRoute_nhop();

            if(meta.count == 0){
              meta.count = 1;
              meta.n_bits = 0;
            }

            // Porta 1
            if((meta.port & (9w1 << (bit<8>)(meta.count - 1))) > 0){
              if(meta.n_bits == 0){
                meta.f_port = meta.count;
              }else if(meta.n_bits >= 1){
                clone_packet((bit<32>)meta.count);
              }
              meta.n_bits = meta.n_bits + 1;
            }

            // Porta 2
            meta.count = meta.count + 1;
            if((meta.port & (9w1 << (bit<8>)(meta.count - 1))) > 0){
              if(meta.n_bits == 0){
                meta.f_port = meta.count;
              }else if(meta.n_bits >= 1){
                clone_packet((bit<32>)meta.count);
              }
              meta.n_bits = meta.n_bits + 1;
            }

            // Porta 3
            meta.count = meta.count + 1;
            if((meta.port & (9w1 << (bit<8>)(meta.count - 1))) > 0){
              if(meta.n_bits == 0){
                meta.f_port = meta.count;
              }else if(meta.n_bits >= 1){
                clone_packet((bit<32>)meta.count);
              }
              meta.n_bits = meta.n_bits + 1;
            }

            do_resubmit_reason1();

      } else if (meta.mymeta.resubmit_reason == 1) {
        //quando o pacote recircular
        standard_metadata.egress_spec = meta.mymeta.f1;
      }

    } else{
        if(hdr.ipv4.diffserv != 55){
          //encaminhamento pacotes de dados (nao possui ToS = 55)
          ipv4_lpm.apply();
          ip_sender_match_table.apply();
        }
        else{
          drop();
        }

    }
  }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

  //novos
  register<enq_qdepth_v>(1) reg_port1_qdepth_0;
  register<enq_qdepth_v>(1) reg_port1_qdepth_1;

  register<enq_qdepth_v>(1) reg_port2_qdepth_0;
  register<enq_qdepth_v>(1) reg_port2_qdepth_1;

  register<enq_qdepth_v>(1) reg_port3_qdepth_0;
  register<enq_qdepth_v>(1) reg_port3_qdepth_1;

  register<enq_qdepth_v>(1) reg_port4_qdepth_0;
  register<enq_qdepth_v>(1) reg_port4_qdepth_1;


  //porta 1
  action r_register_manipulation_port1_qdepth0(){
        //lendo o registrador porta1_fila0 na posicao 0 (so tem essa) e armazenado 
        bit<32> qdepth_value;
        reg_port1_qdepth_0.read(qdepth_value,0);
        hdr.int_info[0].port1_enq_qdepth0 = qdepth_value;
  }

  action r_register_manipulation_port1_qdepth1(){
      //lendo o registrador porta1_fila1 na posicao 0 (so tem essa) e armazenado 
      bit<32> qdepth_value;
      reg_port1_qdepth_1.read(qdepth_value,0);
      hdr.int_info[0].port1_enq_qdepth1 = qdepth_value;
  }

  //porta 2
  action r_register_manipulation_port2_qdepth0(){
        //lendo o registrador porta2_fila0 na posicao 0 (so tem essa) e armazenado 
        bit<32> qdepth_value;
        reg_port2_qdepth_0.read(qdepth_value,0);
        hdr.int_info[0].port2_enq_qdepth0 = qdepth_value;
  }

  action r_register_manipulation_port2_qdepth1(){
      //lendo o registrador porta2_fila1 na posicao 0 (so tem essa) e armazenado 
      bit<32> qdepth_value;
      reg_port2_qdepth_1.read(qdepth_value,0);
      hdr.int_info[0].port2_enq_qdepth1 = qdepth_value;
  }

  
  //porta 3
  action r_register_manipulation_port3_qdepth0(){
        //lendo o registrador porta3_fila1 na posicao 0 (so tem essa) e armazenado
        bit<32> qdepth_value;
        reg_port3_qdepth_0.read(qdepth_value,0);
        hdr.int_info[0].port3_enq_qdepth0 = qdepth_value;
  }

  action r_register_manipulation_port3_qdepth1(){
      //lendo o registrador porta3_fila1 na posicao 0 (so tem essa) e armazenado 
      bit<32> qdepth_value;
      reg_port3_qdepth_1.read(qdepth_value,0);
      hdr.int_info[0].port3_enq_qdepth1 = qdepth_value;
  }

  //porta 4
  action r_register_manipulation_port4_qdepth0(){
        //lendo o registrador porta4_fila0 na posicao 0 (so tem essa) e armazenado
        bit<32> qdepth_value;
        reg_port4_qdepth_0.read(qdepth_value,0);
        hdr.int_info[0].port4_enq_qdepth0 = qdepth_value;
  }

  action r_register_manipulation_port4_qdepth1(){
      //lendo o registrador porta4_fila1 na posicao 0 (so tem essa) e armazenado 
      bit<32> qdepth_value;
      reg_port4_qdepth_1.read(qdepth_value,0);
      hdr.int_info[0].port4_enq_qdepth1 = qdepth_value;
  }



  //porta 1
  action w_register_manipulation_port1_qdepth0(){
    reg_port1_qdepth_0.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }

  action w_register_manipulation_port1_qdepth1(){
    reg_port1_qdepth_1.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }



  //porta 2
  action w_register_manipulation_port2_qdepth0(){
    reg_port2_qdepth_0.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }

  action w_register_manipulation_port2_qdepth1(){
    reg_port2_qdepth_1.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }


  //porta 3
  action w_register_manipulation_port3_qdepth0(){
    reg_port3_qdepth_0.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }

  action w_register_manipulation_port3_qdepth1(){
    reg_port3_qdepth_1.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }

  //porta 4
  action w_register_manipulation_port4_qdepth0(){
    reg_port4_qdepth_0.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }

  action w_register_manipulation_port4_qdepth1(){
    reg_port4_qdepth_1.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
  }


  action drop() {
    mark_to_drop(standard_metadata);
  }

  action add_int_info(bit<32> sw_id, bit<32> rep_count) {
    hdr.int_option.remaining_hop_count = hdr.int_option.remaining_hop_count + 1;
    hdr.int_info.push_front(1);
    hdr.int_info[0].setValid();
    hdr.int_info[0].sw_id = (bit<32>)sw_id;
    hdr.int_info[0].ingress_port=(bit<32>)standard_metadata.ingress_port;
    hdr.int_info[0].egress_port=(bit<32>)standard_metadata.egress_port;
    if (standard_metadata.egress_port == 1){
      hdr.int_info[0].replicate_count=0;
    } else{
      hdr.int_info[0].replicate_count=(bit<32>)rep_count;
    }
    hdr.int_info[0].ingress_global_timestamp=(bit<64>)standard_metadata.ingress_global_timestamp;
    hdr.int_info[0].egress_global_timestamp=(bit<64>)standard_metadata.egress_global_timestamp;
    hdr.int_info[0].enq_timestamp=(bit<32>)standard_metadata.enq_timestamp;
    //leituras nos registradores dos enq_qdepth feitas em outras actions
      //hdr.int_info[0].enq_qdepth=(bit<32>)standard_metadata.enq_qdepth;
    hdr.int_info[0].deq_timedelta=(bit<32>)standard_metadata.deq_timedelta;
    hdr.int_info[0].deq_qdepth=(bit<32>)standard_metadata.deq_qdepth;
   
    hdr.int_info[0].priority = (priority_v)standard_metadata.priority; //definindo no ingresso (0)
    hdr.int_info[0].qid = (qid_v)standard_metadata.qid; //se o priority foi 0 no ingress, aqui vai ser tbm

    //leituras dos registradores
    r_register_manipulation_port1_qdepth0();
    r_register_manipulation_port1_qdepth1();

    r_register_manipulation_port2_qdepth0();
    r_register_manipulation_port2_qdepth1();

    r_register_manipulation_port3_qdepth0();
    r_register_manipulation_port3_qdepth1();

    r_register_manipulation_port4_qdepth0();
    r_register_manipulation_port4_qdepth1();

  }

  table addIntInfo {
    key = {
      hdr.ethernet.etherType : exact;
    }
    actions = {
      add_int_info;
      NoAction;
    }
    default_action = NoAction();
  }
  apply {

    
    // Prune multicast packet to ingress port to preventing loop
    if (standard_metadata.egress_port == standard_metadata.ingress_port) {
      drop();
    } 
    //verificando se eh um pacote de dados para fazer a escrita do registrador correspondente a porta-fila que ele esta passando
    else if(!hdr.int_option.isValid()){
      if(standard_metadata.qid == 0 && standard_metadata.egress_port == 1){
        w_register_manipulation_port1_qdepth0();
      }
      else if(standard_metadata.qid == 1 && standard_metadata.egress_port == 1){
        w_register_manipulation_port1_qdepth1();
      }
      else if(standard_metadata.qid == 0 && standard_metadata.egress_port == 2){
        w_register_manipulation_port2_qdepth0();
      }
      else if(standard_metadata.qid == 1 && standard_metadata.egress_port == 2){
        w_register_manipulation_port2_qdepth1();
      }
      else if(standard_metadata.qid == 0 && standard_metadata.egress_port == 3){
        w_register_manipulation_port3_qdepth0();
      }
      else if(standard_metadata.qid == 1 && standard_metadata.egress_port == 3){
        w_register_manipulation_port3_qdepth1();
      }
      else if(standard_metadata.qid == 0 && standard_metadata.egress_port == 4){
        w_register_manipulation_port4_qdepth0();
      }
      else if(standard_metadata.qid == 1 && standard_metadata.egress_port == 4){
        w_register_manipulation_port4_qdepth1();
      } 
    }


    //pacote de telemetria de recirculacao (primeira porta)
    else if (meta.mymeta.resubmit_reason == 1) {
      //r_last_egress_global_timestamp.read(meta.m_last_egress_sampling_timestamp.h_last_egress_sampling_timestamp,(bit<32>)standard_metadata.egress_port);
      //nao pega todo pacote de telemetria, baseado num tempo de 50 milisegundos
      //pensar aqui no que faremos
      //if(standard_metadata.egress_global_timestamp - meta.m_last_egress_sampling_timestamp.h_last_egress_sampling_timestamp > 50000) {
      addIntInfo.apply();
      //r_last_egress_global_timestamp.write((bit<32>)standard_metadata.egress_port, standard_metadata.egress_global_timestamp);
      //}
    } 
      
    //qualquer outra porta que nao seja a de cima (primeira porta)
    else {
      //remove o historico
      //hdr.int_option.remaining_hop_count = 0;
      //hdr.int_info.pop_front(MAX_HOPS);
      addIntInfo.apply();
    }
  }

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
  apply {
    update_checksum(
    hdr.ipv4.isValid(),
        { hdr.ipv4.version,
          hdr.ipv4.ihl,
          hdr.ipv4.diffserv,
          hdr.ipv4.totalLen,
          hdr.ipv4.identification,
          hdr.ipv4.flags,
          hdr.ipv4.fragOffset,
          hdr.ipv4.ttl,
          hdr.ipv4.protocol,
          hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr },
        hdr.ipv4.hdrChecksum,
        HashAlgorithm.csum16);
  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.srcRoute);
    //packet.emit(hdr.ipv4);
    packet.emit(hdr.int_option);
    packet.emit(hdr.int_info);
    packet.emit(hdr.ipv4);
  }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;
