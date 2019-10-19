#!/usr/bin/python

import pprint
import struct
from copy import copy
from optparse import OptionParser, OptionValueError
from os.path import expandvars
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

    # Create a client socket on which to send requests to other DNS
    # servers:
    setdefaulttimeout(TIMEOUT)
    cs = socket(AF_INET, SOCK_DGRAM)

    # Create a server socket to accept incoming connections from DNS
    # client resolvers (stub resolvers):
    ss = socket(AF_INET, SOCK_DGRAM)
    # Set timeout so no reply exceeds 60s TODO: Add message if failed

    ss.bind(("127.0.0.1", options.port))
    serveripaddr, serverport = ss.getsockname()
    ss.settimeout(60)
    # NOTE: In order to pass the test suite, the following must be the
    # first line that your dns server prints and flushes within one
    # second, to sys.stdout:
    print("%s: listening on port %d" % (sys.argv[0], serverport))
    sys.stdout.flush()

    # Main Server Loop
    while 1:

        # try:
        (data, client_address) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes

        if not data and not Header.fromData(data)._qdcount == 1:
            log.error("client provided no data")
            continue

        queryHeader = Header.fromData(data)
        queryQuestion = QE.fromData(data, offset=12)

        def getAnswer(domain):
            def addToCache(domain, targetAddr):
                cReqHeader = Header(
                    50000,
                    opcode=Header.OPCODE_QUERY,
                    rcode=Header.RCODE_NOERR,
                    qr=0,  # 1 -response, 0=query
                    qdcount=1,  # Questions #
                    nscount=0,  # NS Entries #
                    ancount=0,  # Answer #
                    arcount=0,  # Addition #
                    aa=False,  # Autho
                    tc=False,  # Truncation
                    rd=False,  # Recursion Desired
                    ra=False,  # Recursion Available
                )
                cReqQuestion = QE(dn=domain, type=QE.TYPE_A)
                payload = cReqHeader.pack() + cReqQuestion.pack()
                cs.sendto(payload, (targetAddr, 53))

                data = cs.recvfrom(512)[0]

                def getRecordsFromData(data):
                    resNS = []
                    resA = []
                    resCNAME = []
                    headerLen = len(Header.fromData(data))
                    questionLen = len(QE.fromData(data, offset=headerLen))
                    offset = headerLen + questionLen
                    while offset < len(data):
                        curRR = RR.fromData(data, offset=offset)

                        def processRR(curRR):
                            # print(currentRR)
                            if type(curRR) == RR_NS:
                                resNS.append(curRR)
                            elif type(curRR) == RR_A:
                                resA.append(curRR)
                            elif type(curRR) == RR_AAAA:
                                pass
                            elif type(curRR) == RR_CNAME:
                                resCNAME.append(curRR)
                            else:
                                logger.log(DEBUG2, "Unknown RR: {}".format(curRR))

                        processRR(curRR[0])

                        offset += curRR[1]
                        # print("offset: {}/{}".format(offset, dataPayloadLen))
                    return resNS, resA, resCNAME

                csResNS, csResA, csResCNAME = getRecordsFromData(data)

                for rr in csResNS:
                    print("Cached NS {}".format(rr.__str__()))
                    nscache.put(rr._dn, rr._nsdn, (time() + rr._ttl), True)
                for rr in csResA:
                    print("Cached A  {}".format(rr.__str__()))
                    acache.put(
                        rr._dn, rr._addr, (time() + rr._ttl), authoritative=False
                    )
                for rr in csResCNAME:
                    print("Cached CNAME  {}".format(rr.__str__()))
                    cnamecache.put(rr._dn, rr._cname, (time() + rr._ttl))

            print(domain.__str__())

            if acache.contains(domain):
                return acache.getIpAddresses(domain)
            else:
                if domain.parent() == DomainName("."):
                    # Domain is TLD
                    addToCache(domain, ROOTNS_IN_ADDR)  # Go to Root NS for TLD IP
                    resIP = InetAddr.fromNetwork(
                        acache.getIpAddresses(nscache.get(domain)[0][0])[0]
                    ).__str__()  # IP of TLD
                    print("IP of {} is {}".format(domain, resIP))
                    return resIP
                else:
                    # Domain is < TLD
                    parentIP = getAnswer(domain.parent())  # Get IP of parent domain
                    print("IP of {} is {}".format(domain.parent(), parentIP))
                    addToCache(
                        domain, parentIP
                    )  # Go to parent to cache current domain records
                    if nscache.contains(domain):
                        # NS record exists for domain
                        if acache.contains(nscache.get(domain)[0][0]):
                            # A record exists for this NS record
                            resIP = InetAddr.fromNetwork(
                                acache.getIpAddresses(nscache.get(domain)[0][0])[0]
                            ).__str__()  # Go to cache to find current domain IP
                        else:
                            # No A record exists for this NS record
                            resIP = getAnswer(nscache.get(domain)[0][0])
                        # NS record points

                    elif acache.contains(domain):
                        # NS record doesn't exist but A record does
                        resIP = InetAddr.fromNetwork(
                            acache.getIpAddresses(domain)[0]
                        ).__str__()
                    elif cnamecache.contains(domain):
                        # NS/A records don't exist but CNAME does
                        resIP = getAnswer(cnamecache.getCanonicalName(domain))
                    else:
                        # There's a problem, the domain wasn't cached
                        raise Exception
                    return resIP

        answerIP = getAnswer(queryQuestion._dn)
        print(answerIP)

        def sendEmptyRes(domain):
            resHeader = Header(
                queryHeader._id,
                opcode=Header.OPCODE_QUERY,
                rcode=Header.RCODE_NOERR,
                qr=1,  # 1 -response, 0=query
                qdcount=1,  # Questions #
                nscount=1,  # NS Entries #
                ancount=0,  # Answer #
                arcount=0,  # Addition #
                aa=False,  # Autho
                tc=False,  # Truncation
                rd=False,  # Recursion Desired
                ra=False,  # Recursion Available
            )
            resQuestion = QE(type=QE.TYPE_A, dn=domain)
            reply = RR_NS(
                DomainName("org."), 172800, DomainName("b0.org.afilias-nst.org.")
            )
            payload = resHeader.pack() + resQuestion.pack() + reply.pack()
            logger.log(DEBUG2, "our reply in full:")
            logger.log(DEBUG2, hexdump(payload))
            ss.sendto(payload, client_address)

        def sendRes(domain, resIP):
            resHeader = Header(
                queryHeader._id,
                opcode=Header.OPCODE_QUERY,
                rcode=Header.RCODE_NOERR,
                qr=1,  # 1 -response, 0=query
                qdcount=1,  # Questions #
                nscount=1,  # NS Entries #
                ancount=0,  # Answer #
                arcount=0,  # Addition #
                aa=False,  # Autho
                tc=False,  # Truncation
                rd=False,  # Recursion Desired
                ra=False,  # Recursion Available
            )
            resQuestion = QE(type=QE.TYPE_A, dn=domain)
            reply = RR_A(domain, 172800, InetAddr(resIP).toNetwork())
            payload = resHeader.pack() + resQuestion.pack() + reply.pack()
            logger.log(DEBUG2, "our reply in full:")
            logger.log(DEBUG2, hexdump(payload))
            ss.sendto(payload, client_address)

        sendRes(queryQuestion._dn, answerIP)
        print("Done")
        # except timeout:
        #   pass
        #    sendReply()


if __name__ == "__main__":
    ncsdns()
