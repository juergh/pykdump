"""Crashlib Python API for CRASH Dumps Tool
"""
# Version number
__version__ = '1.0'

# Copyright notice string
__copyright__ = """\
(C) Copyright 2017 Hewlett Packard Enterprise Development LP
Author: Alex Sidorenko <asid@hpe.com>
"""

# This directory contains tests for special cases, when we know 
# exactly what is wrong. These problems are eventually fixed, so
# we might remove some modules later
#
# each module should define 'do_check()' subroutine

import importlib

__modules = ("centrify", )

def check_specialcases(v = 0):
    # As these are ad-hoc test, they are not guaranteed
    # to work on all kernels. So we run them catching exceptions
    for modname in __modules:
        try:
            #print("Running {} test".format(modname))
            mod = importlib.import_module("."+modname, "LinuxDump.specialcases")
            mod.do_check()
        except Exception as val:
            #print("Error in ad-hoc test {}, {}".format(modname, val))
            pass
