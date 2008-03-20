"""Crashlib Python API for CRASH Dumps Tool
"""
# Vversion number
__version__ = '0.2'

# Copyright notice string
__copyright__ = """\
Copyright (c) 2006,2007 Alex Sidorenko; mailto:asid@lhp.com
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.
"""

#__all__ = ["proto", "routing"]

import socket, struct, re
from socket import ntohs

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

