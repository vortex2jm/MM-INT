from mininet.log import info
from mininet.topo import Topo

class INTTopo(Topo):

    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, solution, thrift_port, pcap_dump, n, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        self.switch_list = []
        self.host_list = []
        self.solution = solution
        self.json_path = f'/home/vagrant/MM-INT/solutions/sol{self.solution}/config/'

        #Edge switch
        info("*** Adding P4Switches (edge)\n")
        e = 4
        for h in range(e):
            switch = self.addSwitch('e%d' % (h + 1),
                                    sw_path = sw_path,
                                    json_path = f"{self.json_path}m-polka-int-edge.json",
                                    thrift_port = thrift_port,
                                    pcap_dump = pcap_dump,
                                    log_console = False) #Test for switch logs
            self.switch_list.append(switch)
            thrift_port = thrift_port + 1

        #Switch core
        info("*** Adding P4Switches (core)\n")
        m = 7
        for h in range(m):
            switch = self.addSwitch('s%d' % (h + 1),
                                    sw_path = sw_path,
                                    json_path = f"{self.json_path}m-polka-int-core.json",
                                    thrift_port = thrift_port,
                                    pcap_dump = pcap_dump,
                                    log_console = False)
            self.switch_list.append(switch)
            thrift_port = thrift_port + 1

        info("*** Adding hosts\n")
        n = 8
        for h in range(n):
            host = self.addHost('h%d' % (h + 1),
                                ip = "10.0.1.%d/24" % (h+1),
                                mac = '00:04:00:00:00:%02x' %h)
            self.host_list.append(host)

        self.addLink(self.host_list[0], self.switch_list[0])    #h1-e1
        self.addLink(self.switch_list[0], self.switch_list[4])  #e1-s1
        self.addLink(self.switch_list[4], self.switch_list[8])  #s1-s5
        self.addLink(self.switch_list[4], self.switch_list[5])  #s1-s2
        self.addLink(self.switch_list[5], self.switch_list[9])  #s2-s6
        self.addLink(self.switch_list[9], self.switch_list[7])  #s6-s4
        self.addLink(self.switch_list[7], self.switch_list[2])  #s4-e3
        self.addLink(self.switch_list[2], self.host_list[2])    #e3-h3
        self.addLink(self.switch_list[9], self.switch_list[10]) #s6-s7
        self.addLink(self.switch_list[10], self.switch_list[3]) #s7-e4
        self.addLink(self.switch_list[3], self.host_list[3])    #e4-h4
        self.addLink(self.switch_list[8], self.switch_list[6])  #s5-s3
        self.addLink(self.switch_list[6], self.switch_list[1])  #s3-e2
        self.addLink(self.switch_list[1], self.host_list[1])    #e2-h2
        self.addLink(self.host_list[4], self.switch_list[0])    #h5-e1 adicionado, provavelmente vai ser e1-eth3
        self.addLink(self.host_list[5], self.switch_list[1])    #h6-e2 adicionado, provavelmente vai ser e2-eth3
        self.addLink(self.host_list[6], self.switch_list[2])    #h7-e3 adicionado, provavelmente vai ser e3-eth3
        self.addLink(self.host_list[7], self.switch_list[3])    #h8-e3 adicionado, provavelmente vai ser e4-eth3
