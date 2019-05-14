#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2018-2019 Red Hat, Inc.
#
# Author: Frank Sorenson <sorenson@redhat.com>
#
# Miscellanous library functions
#
#
# Contributors:
# - Kyle Walker: get_per_cpu()
# - Dave Wysochanski: Rename script and cleanup for upstream submit
# --------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

from __future__ import print_function
from pykdump.API import *

def obj_is_inttype(obj):
    if type(obj) == type(0) or type(obj):
        return 1
    return 0

def obj_is_floattype(obj):
    return isinstance(obj, float)

def flags_to_string(flags, strings):
    result = []
    for name, val in strings.items():
        if flags & (1 << val):
            result.append(name)
    return "|".join(result)

def defines_to_string(match_val, strings):
    for name, val in strings.items():
        if match_val == val:
            return name
    return "UNKNOWN"

def indent_str(lvl):
    return "{spaces}".format(spaces = ' ' * 4 * lvl)

def indent(lvl):
    print(indent_str(lvl), end="")

def val_to_units_string(val, base, custom_strings=None):
    if custom_strings == None:
        if base == "SI":
            base = 1000
            unit_strings = [ "", "K", "M", "G", "T", "P", "E", "Z", "Y" ]
        elif base == 1000:
            unit_strings = [ " Bytes", "KB", "MB", "GB", "TB", "PB", "EB"\
                             "ZB", "YB" ]
        elif base == 1024:
            unit_strings = [ " Bytes", "KiB", "MiB", "GiB", "TiB", "PiB",
                             "EiB", "ZiB", "YiB" ]
        else:
            base = 1
    else:
        unit_strings = custom_strings

    if base == 1:
        return "{}".format(val)

    import math

    print("unit strings: {}".format(unit_strings))

    i = int(math.floor(math.log(val, base)))
    divider = math.pow(base, i)
    fmt = "{:.0f} {}" if (int(val/divider) == val/divider) else "{:.2f} {}"
    return fmt.format(val/divider, unit_strings[i])

def get_enum_info(enum_name):
    try:
        _S_enum_info = EnumInfo("enum " + enum_name)
        return _S_enum_info
    except:
        return None

def get_enum_string(val, enum_name):
    str = "UNKNOWN"
    try:
        _S_enum_info = get_enum_info(enum_name)
        if _S_enum_info is None:
            return str
        try:
            _enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
            str = _enum_key_list[val]
        except: # no idea
            pass
    except:
        pass
    return str

def get_enum_bit_string(val, enum_name):
    str = "UNKNOWN"
    try:
        _S_enum_info = get_enum_info(enum_name)
        if _S_enum_info is None:
            return str
        try:
            _enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
            str = _enum_key_list[val.bit_length() - 1]
        except:
            pass
    except: # no idea
        pass
    return str

def print_enum_bit(val, enum_name):
    str = get_enum_bit_string(val, enum_name)
    print("{}".format(str))
    return str

def get_enum_tag_value(tag, enum_name):
    _S_enum_info = get_enum_info(enum_name)
    if _S_enum_info is None:
        return None
    try:
        _enum_key_list = sorted(_S_enum_info, key=lambda x: _S_enum_info[x])
        for k in _enum_key_list:
            if k == tag:
                return _S_enum_info[k]
    except:
        print("exception in get_enum_tag_value")
        pass
    return None

# attempt to be smart about interpreting the passed arg
#
# ambiguous paterns which could be interpreted wrong:
# hex value: ^b[01]*$
#    no '0x' prefix, but starts with 'b' and remainder is all '0' or '1'
#    could be interpreted as binary
# hex value: ^[1-9][0-9]*$
#    no '0x' prefix, but contains only decimal digits
#    could be interpreted as decimal
# symbol name:  ^b[01]*$
#    symbol name that starts with 'b' and remainder is all '0' or '1'
#    could be interpreted as binary
# other strange symbol names, etc.
def arg_value(arg):
    try:
        if '.' in arg:
            return float(arg)
        if arg.lower().startswith('0x'):
            return int(arg, 16)
        elif arg.startswith('0') and all(c in string.octdigits for c in arg):
            return int(arg, 8)
        elif all(c in string.digits for c in arg):
            return int(arg, 10)
        elif arg.startswith('b') and all(c in '01' for c in arg[1:]):
            return int(arg[1:], 2)
        elif all(c in string.hexdigits for c in arg):
            return int(arg, 16)
        elif symbol_exists(arg):
            return sym2addr(arg)
        else:
            return int(arg,0)
#    except ValueError:
    except:
#        print("Unable to determine value for '{}'".format(arg))
        pass
        return 0

def call_foreach_argv(func):
    for arg in sys.argv:
        addr = arg_value(arg)
        if addr != 0:
            func(addr, rlvl=DEFAULT_RLVL)

class get_per_cpu():
    def __init__(self):
        self.cpu      = {}
        self.raw_list = exec_crash_command("p __per_cpu_start").split("\n")
        self.parse_list()
    def parse_list(self):
        count = 0
        for entry in self.raw_list:
            if ":" in entry:
                if "ff" in entry:
                    self.cpu[count] = "0x" + entry.split()[-1]
                    count += 1
                    self.count = count
    def per_cpu_ptr(self, cpu, pointer):
        return int(self.cpu[cpu], 16) + pointer
    def per_cpu_struct(self, cpu, pointer, structtype):
        return readSU("struct " + structtype,
                      (int(self.cpu[cpu], 16) + int(pointer)))
    def sum_values(self, struct):
        sum = 0
        for cpu in range(0, self.count):
            sum += readU64(self.per_cpu_ptr(cpu, struct))
            return sum
    def __repr__(self):
        retstr = "per-cpu:"
        for selectedcpu in self.cpu.keys():
            retstr = "%s\n%s%3s: %s" %(retstr, SPACER, selectedcpu,
                                       self.cpu[selectedcpu])
        return retstr

# vim: sw=4 ts=4 noexpandtab
