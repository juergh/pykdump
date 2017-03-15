#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import re

from pykdump.API import *

import datetime


# Try a chain of dereferences one by one, return proper subroutine
# e.g. ["timekeeper.xtime.tv_sec", "timekeeper.xtime_sec",
#        "shadow_timekeeper.xtime_sec", "xtime.tv_sec"]
#
# After some redesign/cleanup this should be probably going to API.py


def conditionalReadSymbol(chain):
    expr = None
    rc = None
    for e1 in chain:
        expr = "PYKD.{}".format(e1)
        try:
            rc = eval(expr)
        except (NameError, KeyError, TypeError):
            pass
        else:
            #print(expr)
            break
    return rc

# Emulating parts of get_xtime algorithm from crash sources
# Tested on RHEL6, RHEL7, SLES12 and Ubuntu Xenial 
_readSyms = ["timekeeper.xtime.tv_sec", "timekeeper.xtime_sec",
            "shadow_timekeeper.xtime_sec", "xtime.tv_sec"]

def get_xtime():
    return conditionalReadSymbol(_readSyms)

re_ts = re.compile(r'\s*\[\s*(\d+)\.\d+\]')
sec = get_xtime()

loglines = exec_crash_command("log").splitlines()

last_line = loglines[-1]
m = re_ts.search(last_line)
if (not m):
    print("No timestamps")
    sys.exit(0)

print(m.group(1))

base = sec - int(m.group(1))

for l in loglines:
    m = re_ts.search(l)
    if (m):
        ts = int(m.group(1))
        print("{} {}".format(datetime.datetime.fromtimestamp(base+ts),l))
    else:
        print(l)
