#!/usr/bin/env python

# --------------------------------------------------------------------
#
# Author: Aleksandr Nesterenko <anesterenko@cloudlinux.com>
#
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

from pykdump.API import *
from LinuxDump.inet import *
from LinuxDump import percpu
from LinuxDump.inet.proto import print_skbuff_head
from LinuxDump.KernLocks import spin_is_locked
import string

from collections import defaultdict
from io import StringIO

__KPROBE_HASH_BITS = 6
__KPROBE_TABLE_SIZE  = (1 << __KPROBE_HASH_BITS)

def get_all_kprobes():
    kprobes_list_result = defaultdict(list)
    ptrsz = sys_info.pointersize
    kprobe_table = sym2addr('kprobe_table')

    if (kprobe_table == 0):
        pylog.warning("kprobe_table not found")
        return
    
    kps = 'struct kprobe'
    if (not struct_exists(kps)):
        pylog.warning("kprobe structures definitions missing")
        return

    offset = member_offset(kps, "hlist")
    for h in readSymbol('kprobe_table'):
        for kp in hlist_for_each_entry(kps, h, "hlist"):
            kprobes_list_result[kp.symbol_name].append(kp) 
           
    return kprobes_list_result

def print_kprobes():
    kprobes_list = get_all_kprobes()
    for k in kprobes_list:
        for kp in kprobes_list[k]:
            print("Kprobe {}".format(kp))
            print("  addr: {}".format(kp.addr))
            print("  opcode: {}".format(kp.opcode))
            print("  pre_handler:\n\t addr {}\n\t name {}".format(
                hex(kp.pre_handler), addr2sym(kp.pre_handler)))
            print("  post_handler:\n\t addr {}\n\t name {}".format(
                hex(kp.post_handler), addr2sym(kp.pre_handler)))
            print("  symbol_name: {}".format(kp.symbol_name))
            print("  addr to sym: {}".format(addr2sym(kp.addr)))
            print("  offset: {}".format(kp.offset))
            print("  flags: {}".format(kp.flags))
            print("=========================================")

print_kprobes()
