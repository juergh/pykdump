#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import re

from pykdump.API import *

import datetime

def get_xtime():
    return PY_select(
        "PYKD.timekeeper.xtime.tv_sec",
        "PYKD.timekeeper.xtime_sec",
        "PYKD.shadow_timekeeper.xtime_sec",
        "PYKD.xtime.tv_sec"
        )


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
