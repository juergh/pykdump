#!/usr/bin/env/python
from pykdump.API import *


__FILE_MODE_FLAGS='''
#define FMODE_READ     0x1
#define FMODE_WRITE    0x2
'''

FILE_MODE_FLAGS=CDefine(__FILE_MODE_FLAGS)
