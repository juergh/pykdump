"""Crashlib Python API for CRASH Dumps Tool
"""
# Version number
__version__ = '0.3'

# Copyright notice string
__copyright__ = """\
(C) Copyright 2006-2013 Hewlett-Packard Development Company, L.P.
 Author: Alex Sidorenko <asid@hp.com>
"""

#__all__ = ["proto", "routing"]

from pykdump.API import *

import socket, struct, re
from socket import ntohs, ntohl, htonl

# Generic stuff, used both by all INET packages
#----------------------------------------------------------------------
def ntodots(n, printzeroes=True):
    if (n == 0):
        if (printzeroes):
            return "0.0.0.0"
        else:
            return "*"
    # 'I' is 'unsigned int' which is 4 bytes both on i386 and AMD64
    return socket.inet_ntoa(struct.pack("I", n))

# If we build the tool on RHEL3, inet_ntop does not support AF_INET6
# A special case is embedded IPv4, e.g.
# ::ffff:192.168.168.50 instead of
# ::ffff:c0a8:a832
def __inet_ntopv6(n4):
    out = []
    ni = []
    p96 = 0
    for i in range(8):
        v = ord(n4[i*2])*256+ord(n4[i*2+1])
        if (i <= 5):
            p96 = (p96 << 16) + v
        ni.append(v)
        out.append('%x' % v)

    if (False and p96 == 0 and ni[7]):
        # IPv4-Compatible IPv6 Addresses
        return '::' + socket.inet_ntoa(n4[12:])
    elif (p96 == 0xffff):
        return '::ffff:' + socket.inet_ntoa(n4[12:])
    s = ":".join(out)
    if (s == "0:0:0:0:0:0:0:0"):
        return '::'
    s =  re.sub('(:0){2,}', ':', s, 1)
    if (s[:2] == '0:'):
        return s[1:]
    else:
        return s

# IPv6 version. We accept both 'struct in6_addr' and .in6u_u6_addr32
def ntodots6(n4, printzeroes=True):
    # 'I' is 'unsigned int' which is 4 bytes both on i386 and AMD64
    if (type(n4) != type([])):
        n4 = n4.in6_u.u6_addr32
    saddr =  struct.pack("IIII", n4[0], n4[1], n4[2], n4[3])
    try:
        return socket.inet_ntop(socket.AF_INET6, saddr)
    except ValueError:
        return __inet_ntopv6(saddr)


#static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
#{
#       return ((a->s6_addr32[0] | a->s6_addr32[1] |
#                (a->s6_addr32[2] ^ htonl(0x0000ffff))) == 0);
#}

def ipv6_addr_v4mapped(in6_addr):
    a = in6_addr.in6_u
    return ((a.u6_addr32[0] | a.u6_addr32[1] | \
             (a.u6_addr32[2] ^ htonl(0x0000ffff))) == 0)

__net_ns = None
__net_all = False
def get_ns_net():
    if (__net_ns):
        return __net_ns
    else:
        return get_nsproxy().net_ns

def net_all():
    return __net_all

def set_ns_net(addr = None):
    global __net_ns, __net_all
    if(addr == None):
        # Reset to default
        nsproxy = get_nsproxy()
        if (not nsproxy):
            # Old kernels - do nothing
            return True
        __net_ns =  get_nsproxy().net_ns
        __net_all = False
    elif (addr == 'all'):
        # Do not change __net_ns but just set __all_net
        # for those commands that know how to intepret it
        __net_all = True
    else:
        addrlist = [long(n) for n in get_net_namespace_list()]
        if (addr in addrlist):
            __net_ns = readSU("struct net", addr)
            print(" *=*=* Using <struct net {:#x} *=*=*".format(addr))
        else:
            # Incorrect value - could not set
            return False
    return True

def get_net_namespace_list():
    net_namespace_list = readSymbol("net_namespace_list")
    return readSUListFromHead(Addr(net_namespace_list), "list",
                              "struct net")
