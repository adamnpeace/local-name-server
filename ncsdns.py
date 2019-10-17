#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxsize as MAXINT
from time import time, sleep

from libs.collections_backport import OrderedDict
from libs.dnslib.RR import *
from libs.dnslib.Header import Header
from libs.dnslib.QE import QE
from libs.inetlib.types import *
from libs.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"


# cache objects
class RR_A_Cache:  # A cache
    """ 
    Cache 
    Methods
    -------
    put()
        Put a domain name (DN) and corresponding ip address into the cache, with an associated TTL
    contains()
        Check if cache contains an IP for a given DN
    getIpAddresses()
    getExpiration()
    getAuthoritative()
    """

    def __init__(self):
        self.cache = (
            dict()
        )  # domain_name -> [(ip_address, expiration_time, authoritative)]

    def put(self, domain_name, ip_addr, expiration, authoritative=False):
        if domain_name not in self.cache:
            self.cache[domain_name] = dict()
        self.cache[domain_name][ip_addr] = (expiration, authoritative)

    def contains(self, domain_name):
        return domain_name in self.cache

    def getIpAddresses(self, domain_name):
        return list(self.cache[domain_name].keys())

    def getExpiration(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][0]

    def getAuthoritative(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][1]

    def __str__(self):
        return str(self.cache)


class CN_Cache:  # Canonical Name Cache
    def __init__(self):
        self.cache = dict()  # domain_name -> (cname, expiration_time)

    def put(self, domain_name, canonical_name, expiration):
        self.cache[domain_name] = (canonical_name, expiration)

    def contains(self, domain_name):
        return domain_name in self.cache

    def getCanonicalName(self, domain_name):
        return self.cache[domain_name][0]

    def getCanonicalNameExpiration(self, domain_name):
        return self.cache[domain_name][1]

    def __str__(self):
        return str(self.cache)


class RR_NS_Cache:  # Nameserver Cache
    def __init__(self):
        self.cache = dict()  # domain_name -> (NS_record,expiration_time, authoritative)

    def put(self, zone_domain_name, name_server_domain_name, expiration, authoritative):
        if zone_domain_name not in self.cache:
            self.cache[zone_domain_name] = OrderedDict()
        self.cache[zone_domain_name][name_server_domain_name] = (
            expiration,
            authoritative,
        )

    def get(self, zone_domain_name):
        list_name_servers = []
        for name_server in self.cache[zone_domain_name]:
            list_name_servers += [
                (
                    name_server,
                    self.cache[zone_domain_name][name_server][0],
                    self.cache[zone_domain_name][name_server][1],
                )
            ]
        return list_name_servers

    def contains(self, zone_domain_name):
        return zone_domain_name in self.cache

    def __str__(self):
        return str(self.cache)


# >>> entry point of ncsdns.py <<<
def ncsdns():
    # Seed random number generator with current time of day:
    now = int(time())
    seed(now)

    # Initialize the pretty printer:
    pp = pprint.PrettyPrinter(indent=3)

    # Initialize the cache data structures
    acache = RR_A_Cache()
    acache.put(
        DomainName(ROOTNS_DN),
        InetAddr(ROOTNS_IN_ADDR),
        expiration=MAXINT,
        authoritative=True,
    )

    nscache = RR_NS_Cache()
    nscache.put(
        DomainName("."), DomainName(ROOTNS_DN), expiration=MAXINT, authoritative=True
    )

    cnamecache = CN_Cache()

    # Parse the command line and assign us an ephemeral port to listen on:
    def check_port(option, opt_str, value, parser):
        if value < 32768 or value > 61000:
            raise OptionValueError("need 32768 <= port <= 61000")
        parser.values.port = value

    parser = OptionParser()
    parser.add_option(
        "-p",
        "--port",
        dest="port",
        type="int",
        action="callback",
        callback=check_port,
        metavar="PORTNO",
        default=0,
        help="UDP port to listen on (default: use an unused ephemeral port)",
    )
    (options, args) = parser.parse_args()

    ################################

    setdefaulttimeout(TIMEOUT)
    cs = socket(AF_INET, SOCK_DGRAM)

    domain = DomainName("www.google.com")

    # outHeader = Header(20001, 0, 0, qr=0, qdcount=1)
    outHeader = Header(
        19876,
        0,
        0,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        qr=False,
        aa=False,
        tc=False,
        rd=False,
        ra=False,
    )
    outQuestion = QE(dn=domain, type=1)
    print("a", hexdump(outHeader.pack()))
    # print("b", hexdump(outQuestion.pack()))
    payload = b"".join([outHeader.pack(), outQuestion.pack()])

    print("Sent", hexdump(payload))
    cs.sendto(payload, (ROOTNS_DN, 53))
    data = cs.recvfrom(512)
    print("Recvd: ", hexdump(data[0]))
    print(data)
    cs.close()


if __name__ == "__main__":
    ncsdns()
