# DNS Poisoning Tool
A tool to perform DNS cache poisoning against vulnerable server

Attack methodology is widely described here: [Kaminsky Attack](http://unixwiz.net/techtips/iguide-kaminsky-dns-vuln.html)

## Requirements
* Scapy (For packet crafting) `pip install scapy`
* Blessing (For coloured terminal) `pip install blessings`
* DNS Python (For initial DNS query)  `pip install dnspython`

Inline requirements installation command pip install:
```pip install scapy blessings dnspython```

## Usage
```
usage: main.py [-h] -t DOMAIN -a ATTACKER_IP -v VICTIM_DNS_IP
               [-bs BAD_SERVER_IP] [-bp BAD_SERVER_PORT] [-ns NS_SERVER]
               [-i INTERFACE] [-at {NORMAL,DAN}] [-m {NORMAL,FAST}]
               [-vm VICTIM_MAC] [-si SECRET_IP] [-sp SECRET_PORT] [-nc]
               [-vb {1,2,3,4}]

DNS Poisoning Attack Tool

optional arguments:
  -h, --help            show this help message and exit
  -t DOMAIN, --target-domain DOMAIN
                        The target domain to spoof
  -a ATTACKER_IP, --attacker-ip ATTACKER_IP
                        Attacker IP address
  -v VICTIM_DNS_IP, --victim-dns-ip VICTIM_DNS_IP
                        The victim DNS IP address
  -bs BAD_SERVER_IP, --bad-server-ip BAD_SERVER_IP
                        The Bad Guy DNS server IP
  -bp BAD_SERVER_PORT, --bad-server-port BAD_SERVER_PORT
                        The Bad Guy DNS server port
  -ns NS_SERVER, --ns-server NS_SERVER
                        The victim authoritative server
  -i INTERFACE, --interface INTERFACE
                        The Network Card interface to use
  -at {NORMAL,DAN}, --attack-type {NORMAL,DAN}
                        The type of attack to perform
  -m {NORMAL,FAST}, --mode {NORMAL,FAST}
                        Mode to use
  -vm VICTIM_MAC, --victim-mac VICTIM_MAC
                        The victim MAC address
  -si SECRET_IP, --secret-ip SECRET_IP
                        IP to bind for the secret fetcher
  -sp SECRET_PORT, --secret-port SECRET_PORT
                        Port to bind for the secret fetcher
  -nc, --no-colors      Suppress coloured terminal output
  -vb {1,2,3,4}, --verbosity {1,2,3,4}
                        Verbosity level
 ```
