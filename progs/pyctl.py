# -*- coding: utf-8 -*-
#

# High-level API built on top of C-moduleCommand to control PyKdump
# behaviour and debugging

# --------------------------------------------------------------------
# (C) Copyright 2006-2019 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Pubic License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# Set global PyKdump options
import sys
import re

from pykdump.API import *

# We just set values in DCache.perm, without checking whether they are used
# or not. So if someone creates a new program using a new global option,
# there will be no need to modify this program
#
# Usage: 'pyctl --set opt1=val1 opt2=val2 ...'
#
# If called without arguments, it prints the whole contents of
# DCache.perm
#
# To clear options, use syntax
# 'pyctl --clear'                - clear all options
# 'pyctl --clear o1 o2 ...'      - clear options o1 o2 ...

argv = sys.argv[1:]
perm = DCache.perm

if (len(argv) == 0):
    print(perm)
    sys.exit(0)

__goodopt = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

def setopts(optlist):
    # Parse arguments, report errors
    for a in optlist:
        spl = a.split('=')
        if (len(spl) != 2):
            print("  Bad argument: {}".format(a))
            sys.exit(1)
        o, v = spl
        # Now check whether o can be used as an attribute
        if (not __goodopt.match(o)):
            print("  Bad argument: {}".format(a))
            sys.exit(2)
        # If option is already set to int/float, convert as
        # needed
        old = perm.get(o, None)
        if (isinstance(old, int)):
            v = int(v)
        elif (isinstance(old, float)):
            v = float(v)
        perm[o] = v

# Clear options (we pass argv with --clear already stripped)
def clearopts(olist = None):
    if (not olist):
        perm.clear()
        return
    for o in olist:
        try:
            del perm[o]
        except KeyError:
            print("    Cannot clear <{}> as it was not set".format(o))

if ( __name__ == '__main__'):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--set",  nargs='+',
                    help="Set options")

    # To differentiate between cases when we use this option
    # without any arguments ot don't use it at all:
    # None if not set
    # [] if set w/o arguments
    parser.add_argument("--ls",  nargs='*',
                    help="List currently set options")
    parser.add_argument("--clear",  nargs='*',
                    help="Clear currently set options")


    o = parser.parse_args()

    if (o.set):
        print("Set: {}".format(o.set))
        setopts(o.set)
    elif (o.ls is not None):
        if (len(o.ls) == 0):
            perm.Dump()
        else:
            print("List: {}".format(o.ls))
    elif (o.clear is not None):
        if (len(o.clear) == 0):
            print(" -- Clearing all options set --")
            clearopts()
        else:
            print("Clearing: {}".format(o.clear))
            clearopts(o.clear)

    #print(DCache.perm.memoizedebug)
