# -*- coding: utf-8 -*-



"""PyKdump Python API for CRASH Dumpanalysis Tool
It is now Python-3 based
"""
# Version number
__version__ = '3.0.2'

import sys

# Copyright notice string
__copyright__ = """\
(C) Copyright 2006-2018 Hewlett Packard Enterprise Development LP
Author: Alex Sidorenko <asid@hpe.com>
"""

# A minimal C-module version that is needed for API to work
minimal_cmod_version = "3.0.2"


# The next subroutines are used for version compatibility control.
# The pure Python code relies on C-module, so that newer versions of
# Python API might work with newer versions of C-module only.
# Normally, everything is packaged in a single file. But as API
# can use Python code from local directory tree, we need a way to check.
# Another reason is that we can mostly update mpykdump.so without
# rebuilding it, just using ZIP command. But if Python code needs newer
# C-module, this will not work

# Versions have numbers like 0.8.0

# C-mod version
try:
    import crash
    __c_mod_version = crash.version
except ImportError:
    __c_mod_version = None

# Split a string with version to itot, i1, i2, i3
# where itot = 10000*i1 + 100*i2 + i3
def __split_version(vers):
    spl = vers.split(".")
    i1 = int(spl[0])
    i2 = int(spl[1])
    if (len(spl) > 2):
        i3 = int(spl[2])
    else:
        i3 = 0
    itot = 10000*i1 + 100*i2 + i3
    return (itot, i1, i2, i3)

def require_cmod_version(vers, c_mod_version =__c_mod_version ):
    spl_cmod = __split_version(c_mod_version)
    spl_python = __split_version(vers)
    if (spl_cmod[0] < spl_python[0]):
        print ("You need to upgrade your C-module")
        print ("Python API requires at least", vers,\
              "and your C-module is", c_mod_version)
        sys.exit(0)

