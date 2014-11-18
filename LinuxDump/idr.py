#!/usr/bin/env python
# -*- coding: utf-8 -*-

# IDR code, similar to idr.c and idr.h

# --------------------------------------------------------------------
# (C) Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
#
# --------------------------------------------------------------------


# To facilitate migration to Python-3, we use future statements/builtins
from __future__ import print_function

from pykdump.API import *

IDR_SIZE = getStructInfo("struct idr_layer")["ary"].array
IDR_BITS = None

for i in range(BITS_PER_LONG):
    if ((IDR_SIZE >> i) & 0x1):
        IDR_BITS = i
        break
IDR_MASK = ((1 << IDR_BITS)-1)

#define MAX_IDR_SHIFT           (sizeof(int) * 8 - 1)

MAX_IDR_SHIFT = INT_SIZE * 8 - 1

#define MAX_IDR_LEVEL ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)
MAX_IDR_LEVEL = ((MAX_IDR_SHIFT + IDR_BITS - 1) / IDR_BITS)
    
#print(IDR_SIZE, IDR_BITS, IDR_MASK)

# fls - find last (most-significant) bit set. Argumwentr is of 'int' type
# Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
__maxbit = (1 << (BITS_PER_INT-1))
def fls(x):
    for i in range(BITS_PER_INT):
        if (x & __maxbit):
            return (BITS_PER_INT - i)
        x <<= 1
    return 0
    

def idr_max(layers):
    #bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);
    __min1 = (layers * IDR_BITS) & INT_MASK
    __min2 = MAX_IDR_SHIFT & INT_MASK
    bits = min(__min1, __min2)
    return (1 << bits) - 1


def idr_find_slowpath(idr, _id):
    if (_id < 0):
        return None
    p = idp.top
    if (not p):
        return None
    n = (p.layer+1) * IDR_BITS
    
    if (_id > idr_max(p.layer + 1)):
        return None
    
    while (n > 0 and p):
        n -= IDR_BITS;
        #    BUG_ON(n != p->layer*IDR_BITS);
        p = p.ary[(_id >> n) & IDR_MASK]

    return p

def idr_for_each(idp):
    #print(idp, idp.layers)
    n = idp.layers * IDR_BITS
    paa = [None]
    p = idp.top
    _max = idr_max(idp.layers)
    _id = 0;
    #print("---n={} _max={}".format(n, _max))
    while (_id >= 0 and _id <= _max):
        #print("  id={}".format(_id))
        while (n > 0 and p):
            n -= IDR_BITS;
            paa.append(p)
            #print(" ++push len={}".format(len(paa)))
            p = p.ary[(_id >> n) & IDR_MASK]
        if (p):
            yield (_id, p)
                   
        _id += 1 << n
        # ASID how C works in this case?
        #if (_id > _max):
        #    break
        while (n < fls(_id)):
            #print(" ...", _id, n, fls(_id))
            n += IDR_BITS
            p = paa.pop()


#print(MAX_IDR_SHIFT)

    
    