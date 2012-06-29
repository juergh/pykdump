#! /usr/bin/env python

# Time-stamp: <12/06/28 11:27:18 alexs>
# Implementing logical records with channels

from __future__ import print_function

import struct

# Reading sized records. We feed data every time when data
# is available and it invokes a provided callback function when chunk is
# ready

class Records(object):
    def __init__(self, cb):
        self.cb = cb
        self.getHeader = True
        self.needtoread = self.hdrsize = 6
        self.buf = []
        self.buflen = 0

    def feedData(self, data):
        ldata = len(data)
        self.buf.append(data)
        self.buflen += ldata
        # Pop data from buffer until there is not enough left
        while (self.buflen >= self.needtoread):
            alldata = ''.join(self.buf)
            sizeddata = alldata[:self.needtoread]
            self.buf = [alldata[self.needtoread:]]
            self.buflen -= self.needtoread
            self.nbytesReady(sizeddata)
    def nbytesReady(self, data):
        if (self.getHeader):
            self.getHeader = False
            self.needtoread = struct.unpack('!i', data[:4])[0]
            self.channel = struct.unpack('!H', data[4:6])[0]
            #print("++Got channel %d, %d bytes to read" % \
            #      (self.channel, self.needtoread))
        else:
            self.getHeader = True
            self.needtoread = self.hdrsize
            #print("++Got data: <%d> bytes" % len(data))
            # Call consumer
            c1, c2 = splitChannel(self.channel)
            self.cb(data, c1, c2)
    # Prepare a record from data and channels
    def packRecord(self, data, c1, c2):
        channel = setChannel(c1, c2)
        size = len(data)
        return struct.pack("!i", size) + struct.pack("!H", channel)+ data    



# Encoding/decoding channels - the same subroutines should be used
# by clients and server

def setChannel(inst, stype):
    assert stype < 4
    channel = (inst << 2) | stype
    assert channel < 65535
    return channel

# Return (inst, stype)
def splitChannel(channel):
    assert (channel > 0 and channel < 65535)
    inst = channel >> 2
    stype = channel & 0x3
    return (inst, stype)
