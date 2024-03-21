/* -*- P4_16 -*- */ //SOLUCAO 1 - SEM REGISTRADOR, SEM CABECALHO POLKA
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x2020;

#define MAX_HOPS 20

typedef bit<32> enq_qdepth_v;

//acho q n precisa
typedef bit<3> priority_v;
typedef bit<5> qid_v;



/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<112>    routeId;
}

header ipv4_t {
  bit<4>  version;
  bit<4>  ihl;
  bit<8>  diffserv; //TOS
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

/*struct polka_t_top {
  macAddr_t dstAddr;
  macAddr_t srcAddr;
  bit<16>   etherType;
  bit<160>   routeId;
}*/

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
  //priority_v priority;
  //qid_v      qid;

  
}

header inthdr_t {
  bit<32>      sw_id;
  bit<32>      ingress_port;
  bit<32>      egress_port;
  bit<32>      replicate_count;
  bit<64>      ingress_global_timestamp;
  bit<64>      egress_global_timestamp;
  bit<32>      enq_timestamp;
  //bit<32>      enq_qdepth;
  bit<32>      deq_timedelta;
  bit<32>      deq_qdepth;
  enq_qdepth_v enq_qdepth; //so vai passar por uma das filas (a que ele esta)
  //enq_qdepth_v enq_qdepth1;
  //n precisa mas eu vo deixar pra mostrar q eh mudavel
  priority_v priority;
  qid_v      qid;
}

struct metadata {
    //acho q daqui n vai uasr nada (n vai clonar)
    bit<112>   routeId;
    bit<16>   etherType;
    bit<1> apply_sr;
    bit<9> port;

    //talvez esse
    bit<8> int_info_remaining;
}

struct headers {
  ethernet_t          ethernet;
  //srcRoute_t          srcRoute; n tem o polka
  //ipv4_t              ipv4;
  intoption_t         int_option;
  inthdr_t[MAX_HOPS]  int_info;
  ipv4_t              ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
        //serve para encapsular
            TYPE_IPV4: parse_ipv4;
            //serve para desencapsular
            TYPE_SRCROUTING: parse_srcRouting;
            default: accept;
        }
    }

    state parse_srcRouting {
        //packet.extract(hdr.srcRoute); n tem o polka
        //transition parse_ipv4;
        transition parse_int_option;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        //transition select(hdr.ethernet.etherType) {
            //TYPE_IPV4: accept;
            //TYPE_SRCROUTING: parse_int_option;
        //}
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


    //fazer parse do header int_info - senao nao consigo remover
    //accept
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
    apply { }
}


/*************************************************************************
**********************  T U N N E L   E N C A P   ************************
*************************************************************************/
control process_tunnel_encap(inout headers hdr,
                            inout metadata meta,
                            inout standard_metadata_t standard_metadata) {
    action tdrop() {
        mark_to_drop(standard_metadata);
    }

    //solucao 3: sem polka.modifiquei as flowtabels todas do e1...e4 pra tirar o routeid tirei o "sr" tambem
    action add_sourcerouting_header(egressSpec_t port, macAddr_t dmac){

        standard_metadata.egress_spec = port;
        //meta.apply_sr = sr; sobre clonagem: n fazer

        hdr.ethernet.dstAddr = dmac;

        //hdr.srcRoute.setValid(); n tem polka
        //hdr.srcRoute.routeId = routeIdPacket; n tem polka

        hdr.int_option.setValid();
        hdr.int_option.ver = 2;
        hdr.int_option.d = 0;
        hdr.int_option.e = 0;
        hdr.int_option.m = 0;
        hdr.int_option.r = 0;
        hdr.int_option.hop_ml = 10;
        hdr.int_option.remaining_hop_count = 0;
        hdr.int_option.instruction_bitmap = 56832;
        hdr.int_option.domain_specific_id = 0x0000;
        
    }

    action add_int_option_header(){
        hdr.int_option.ver = 2;
        hdr.int_option.d = 0;
        hdr.int_option.e = 0;
        hdr.int_option.m = 0;
        hdr.int_option.r = 0;
        hdr.int_option.hop_ml = 10;
        hdr.int_option.remaining_hop_count = 0;
        hdr.int_option.instruction_bitmap = 56832;
        hdr.int_option.domain_specific_id = 0x0000;

        hdr.int_option.setValid();
    }

    table tunnel_encap_process_sr {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            add_sourcerouting_header;
            add_int_option_header;
            tdrop;
        }
        size = 1024;
        default_action = tdrop();
    }

    apply {
        tunnel_encap_process_sr.apply();
        /*if(meta.apply_sr!=1){
            //hdr.srcRoute.setInvalid(); //nao sei mas n tem polka entao
        }else{
            hdr.ethernet.etherType = TYPE_SRCROUTING;
        }*/

        hdr.ethernet.etherType = TYPE_SRCROUTING;

    }

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

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port){
      //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

      hdr.ethernet.dstAddr = dstAddr;

      standard_metadata.egress_spec = port;

      hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    table ipv4_lpm{
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

    table teste {
        key = {
            standard_metadata.priority: exact;
        }
        actions = {
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table teste2 {
        key = {
            standard_metadata.qid: exact;
        }
        actions = {
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    } 

    apply {
      //se for um pacote enviado pelo sender (TOS = 55 + SEM CABECALHO INT/POLKA)
      if (hdr.ipv4.isValid() && hdr.ethernet.etherType != TYPE_SRCROUTING ) { //55 em decimal, 37 em hexa
              if (hdr.ipv4.diffserv == 55){
                process_tunnel_encap.apply(hdr, meta, standard_metadata); //adiciona o polka (removendo isso pra essa solucao3)
                standard_metadata.priority = 1; //coleta de int vai passar na 0  em todos swithces - nao importa (le de tds registradores)
                teste.apply();
                teste2.apply();
              }
              else{
                //encaminhamento comum ipv4, pacote de dados
                ipv4_lpm.apply();
              }
      }
      //pacote chegando num edge, remover o INT
      else if (hdr.ethernet.etherType == TYPE_SRCROUTING) {
              hdr.ethernet.etherType = TYPE_IPV4;
              //hdr.srcRoute.setInvalid(); n tem polka

              //remover toda a pilha int
              hdr.int_info.pop_front(MAX_HOPS);

              //além de excluir, tem que invalidar o int_info
              hdr.int_option.setInvalid();
              //hdr.int_info.setInvalid();

              if (standard_metadata.ingress_port == 1){
                standard_metadata.egress_spec = 2; //formalizou que todos os switches de borda, a porta 1 esta enviando pro host
              } else if (standard_metadata.ingress_port == 2){
                standard_metadata.egress_spec = 1;
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

    table teste {
        key = {
            standard_metadata.priority: exact;
        }
        actions = {
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table teste2 {
        key = {
            standard_metadata.qid: exact;
        }
        actions = {
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }              
    apply { 
      teste.apply();
      teste2.apply();

     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        //packet.emit(hdr.srcRoute);
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
