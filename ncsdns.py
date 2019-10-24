#!/usr/bin/python

import pprint
import struct
from builtins import Exception
from copy import copy
from optparse import OptionParser, OptionValueError
from random import randint, seed
from socket import *
from sys import exit
from sys import maxsize as MAXINT
from time import sleep, time

from libs.collections_backport import OrderedDict
from libs.dnslib.Header import Header
from libs.dnslib.QE import QE
from libs.dnslib.RR import *
from libs.inetlib.types import *
from libs.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"


# cache objects
class RR_A_Cache:
    def __init__(self):
        self.cache = (
            dict()
        )  # domain_name -> [(ip_address, expiration_time, authoritative)]

    def put(self, domain_name, ip_addr, expiration, authoritative=False):
        if type(ip_addr) is not InetAddr:
            raise TypeError
        if domain_name not in self.cache:
            self.cache[domain_name] = dict()
        self.cache[domain_name][ip_addr] = (expiration, authoritative)

    def contains(self, domain_name):
        if domain_name in self.cache:
            for ip in list(self.cache[domain_name].keys()):
                if self.getExpiration(domain_name, ip) > time():
                    return True
        return False

    def getIpAddresses(self, domain_name):
        return [
            ip
            for ip in list(self.cache[domain_name].keys())
            if self.getExpiration(domain_name, ip) > time()
        ]

    def getExpiration(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][0]

    def getAuthoritative(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][1]

    def getRRs(self, domain_name):
        rrs = []
        for ip in list(self.cache[domain_name].keys()):
            rrs.append(
                RR_A(
                    domain_name,
                    int(self.cache[domain_name][ip][0] - time()),
                    ip.toNetwork(),
                )
            )
        return rrs

    def __str__(self):
        return str(self.cache)


class CN_Cache:
    def __init__(self):
        self.cache = dict()  # domain_name -> (cname, expiration_time)

    def put(self, domain_name, canonical_name, expiration):
        self.cache[domain_name] = (canonical_name, expiration)

    def contains(self, domain_name):
        if domain_name in self.cache:
            if self.getCanonicalNameExpiration(domain_name) > time():
                return True
        return False

    def getCanonicalName(self, domain_name):
        if self.getCanonicalNameExpiration(domain_name) > time():
            return self.cache[domain_name][0]

    def getCanonicalNameExpiration(self, domain_name):
        return self.cache[domain_name][1]

    def getRR(self, domain_name):
        return RR_CNAME(
            domain_name,
            int(self.cache[domain_name][1] - time()),
            self.cache[domain_name][0],
        )

    def __str__(self):
        return str(self.cache)


class RR_NS_Cache:
    def __init__(self):
        self.cache = (
            dict()
        )  # domain_name -> (NS_record -> (expiration_time, authoritative))

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
            if self.cache[zone_domain_name][name_server][0] > time():
                list_name_servers += [
                    (
                        name_server,
                        self.cache[zone_domain_name][name_server][0],
                        self.cache[zone_domain_name][name_server][1],
                    )
                ]
        return list_name_servers

    def getRRs(self, zone_domain_name):
        rrs = []
        for name_server in self.cache[zone_domain_name]:
            rrs.append(
                RR_NS(
                    zone_domain_name,
                    int(self.cache[zone_domain_name][name_server][0] - time()),
                    name_server,
                )
            )
        return rrs

    def contains(self, zone_domain_name):
        if zone_domain_name in self.cache:
            for name_server in self.cache[zone_domain_name]:
                if self.cache[zone_domain_name][name_server][0] > time():
                    return True
        return False

    def __str__(self):
        return str(self.cache)


# >>> entry point of ncsdns.py <<<

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

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print("%s: listening on port %d" % (sys.argv[0], serverport))
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)


def isInCache(dn):
    # 0 - not in cache, 1 - in or ns>a, 2 - in ns\a, 3 - in cname
    if acache.contains(dn):
        return 1
    elif nscache.contains(dn):
        if acache.contains(nscache.get(dn)[0][0]):
            return 1
        else:
            return 2
    elif cnamecache.contains(dn):
        return 3
    else:
        return 0


def getIpsFromCache(dn):
    # Get cached IP addresses for a given DN
    if acache.contains(dn):
        resIps = [(ip).__str__() for ip in acache.getIpAddresses(dn)]
    elif nscache.contains(dn):
        resIps = []
        for ns in nscache.get(dn):
            if acache.contains(ns[0]):
                for ip in acache.getIpAddresses(ns[0]):
                    resIps.append(str(ip))
    return resIps


def getGlueNamesFromCache(dn):
    # Get cached DNs for a given DN
    resIps = []
    if nscache.contains(dn):
        resIps = [ns[0] for ns in nscache.get(dn)]
    else:
        resIps = [cnamecache.getCanonicalName(dn)]
    return resIps


# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:

    ss.settimeout(None)
    (data, client_address) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes
    if not data and not Header.fromData(data)._qdcount == 1:
        logger.log(DEBUG2, "client provided no data")
        continue
    ss.settimeout(60)

    queryHeader = Header.fromData(data)
    queryQuestion = QE.fromData(data, offset=12)
    queryDomain = queryQuestion._dn
    print("Query received from client is:\n%s" % (hexdump(data)))
    count = 2
    stack = []
    try:

        def recursiveLookup(dn: DomainName) -> str:
            if type(dn) == RR_SOA:
                return dn
            print("Lookup", dn)
            cacheStatus = isInCache(dn)
            if cacheStatus == 1:
                print("Found IP for", dn)
                return getIpsFromCache(dn)[0]
            elif cacheStatus == 2:
                print("Found NS for", dn)
                toLookup = getGlueNamesFromCache(dn)[count]
            elif cacheStatus == 3:
                print("Found CN for", dn)
                toLookup = cnamecache.getCanonicalName(dn)
                stack.append(dn)
            elif cacheStatus == 0:
                # No data is cached
                print("No cached data for", dn)
                payload = Header(
                    50000,
                    opcode=Header.OPCODE_QUERY,
                    rcode=Header.RCODE_NOERR,
                    qr=0,  # 1 -response, 0=query
                    qdcount=1,  # Questions #
                ).pack()
                payload += QE(dn=dn, type=QE.TYPE_A).pack()
                parentIp = recursiveLookup(dn.parent())
                if type(parentIp) == RR_SOA:
                    return parentIp
                cs.sendto(payload, (parentIp, 53))
                data = cs.recvfrom(512)[0]

                # Unpack client response data
                headerLen = len(Header.fromData(data))
                questionLen = len(QE.fromData(data, offset=headerLen))
                offset = headerLen + questionLen
                while offset < len(data):
                    # Iterate by framesize
                    curFrame = RR.fromData(data, offset=offset)
                    rr = curFrame[0]

                    if type(rr) == RR_NS:
                        print("Caching NS", rr.__str__())
                        nscache.put(rr._dn, rr._nsdn, (time() + rr._ttl), True)
                    elif type(rr) == RR_A:
                        print("Caching A", rr.__str__())
                        acache.put(
                            rr._dn,
                            InetAddr.fromNetwork(rr._addr),
                            (time() + rr._ttl),
                            authoritative=False,
                        )
                    elif type(rr) == RR_AAAA:
                        pass
                    elif type(rr) == RR_CNAME:
                        print("Caching CNAME", rr.__str__())
                        cnamecache.put(rr._dn, rr._cname, (time() + rr._ttl))
                        stack.append(rr._dn)
                    elif type(rr) == RR_SOA:
                        print("Exiting: Found SOA", rr.__str__())
                        return rr
                    else:
                        logger.log(DEBUG2, "Unknown RR: {}".format(rr))

                    offset += curFrame[1]

                toLookup = dn
            print("Looking again for", toLookup)
            cacheStatus = isInCache(toLookup)

            if cacheStatus in [2, 3]:
                # No glues exist for this dn
                reloadGlues = recursiveLookup(getGlueNamesFromCache(toLookup)[0])
                if type(reloadGlues) == RR_SOA:
                    return reloadGlues
                resIps = getIpsFromCache(getGlueNamesFromCache(toLookup)[0])
            elif cacheStatus == 3:
                resIps = recursiveLookup(getGlueNamesFromCache(toLookup)[0])
            else:
                resIps = getIpsFromCache(toLookup)
            return resIps[0]

        res = recursiveLookup(queryQuestion._dn)
        if type(res) == RR_SOA:
            # SOA should be returned straight back to ns client
            reply = (
                Header(
                    queryHeader._id,
                    opcode=Header.OPCODE_QUERY,
                    rcode=Header.RCODE_NOERR,
                    qr=1,  # 1 -response, 0=query
                    qdcount=1,  # Questions #
                    nscount=0,  # NS Entries #
                    ancount=1,  # Answer #
                    arcount=0,  # Addition #
                ).pack()
                + queryQuestion.pack()
                + res.pack()
            )
        else:
            ancount = 0
            arcount = 0
            nscount = 0

            reply = queryQuestion.pack()
            # Give records for last domain in chain
            if stack == []:
                lastDn = queryQuestion._dn
            else:
                lastDn = cnamecache.getCanonicalName(stack[-1])
                for dn in stack:
                    reply += cnamecache.getRR(dn).pack()
                    ancount += 1
            try:

                for a_rr in acache.getRRs(lastDn):
                    reply += a_rr.pack()
                    ancount += 1
                nss = []
                if nscache.contains(lastDn.parent()):
                    for ns_rr in nscache.getRRs(lastDn.parent()):
                        reply += ns_rr.pack()
                        nss.append(ns_rr._nsdn)
                        nscount += 1
                for ns in nss:
                    if acache.contains(ns):
                        for a_rr in acache.getRRs(ns):
                            reply += a_rr.pack()
                            arcount += 1
            except:
                pass

            reply = (
                Header(
                    queryHeader._id,
                    opcode=Header.OPCODE_QUERY,
                    rcode=Header.RCODE_NOERR,
                    qr=1,  # 1 -response, 0=query
                    qdcount=1,  # Questions #
                    nscount=nscount,  # NS Entries #
                    ancount=ancount,  # Answer #
                    arcount=arcount,  # Addition #
                ).pack()
                + reply
            )
        logger.log(DEBUG2, "our reply in full:")
        logger.log(DEBUG2, hexdump(reply))

        ss.sendto(reply, client_address)
        print("Success!")
    except:
        reply = (
            Header(
                queryHeader._id,
                opcode=Header.OPCODE_QUERY,
                rcode=Header.RCODE_SRVFAIL,
                qr=1,  # 1 -response, 0=query
                qdcount=1,  # Questions #
                nscount=0,  # NS Entries #
                ancount=0,  # Answer #
                arcount=0,  # Addition #
            ).pack()
            + queryQuestion.pack()
        )
        ss.sendto(reply, client_address)
        print("Failed")
