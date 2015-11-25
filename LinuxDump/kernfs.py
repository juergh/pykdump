#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2014-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# To facilitate migration to Python-3, we use future statements/builtins
from __future__ import print_function

import sys

from pykdump.API import *

from LinuxDump.fs import *
from LinuxDump.trees import *

def kernfs_active(kn):
    return kn.active >= 0

#define rb_to_kn(X) rb_entry((X), struct kernfs_node, rb)
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

def rb_to_kn(node):
    return container_of(node, "struct kernfs_node", "rb")


#define KERNFS_TYPE_MASK	0x000f
KERNFS_TYPE_MASK = 0x000f
KERNFS_DIR = enumerator_value("KERNFS_DIR")
KERNFS_FILE = enumerator_value("KERNFS_FILE")
KERNFS_LINK = enumerator_value("KERNFS_LINK")

def kernfs_node_type(kn):
    return kn.flags & KERNFS_TYPE_MASK


# Iterate through directory, return kn
def kndir_iterate(pos):
    for kn in for_all_rbtree(pos.dir.children, "struct kernfs_node", "rb"):
        if (kernfs_active(pos)):
            yield kn

# Walk/print directory
def walk_kdir(dirkn, indent = 0):
    for kn in kndir_iterate(dirkn):
        sindent = ' ' * indent
        node_type =  kernfs_node_type(kn)
        print(sindent,  kn.name, node_type)
        if (node_type == KERNFS_DIR):
            walk_kdir(kn, indent+2)
        elif (node_type == KERNFS_LINK):
            knlink = kn.symlink.target_kn
            print(sindent, "  ->", kernfs_fullpath(knlink))

# similar to  decode_sysfs_dirent,
# return (name, type) wheer type is one of '.' '/' '@'
def decode_kernfs_node(kn):
    name = kn.name
    node_type =  kernfs_node_type(kn)
    if (node_type == KERNFS_DIR):
        nt = '/'
    elif (node_type == KERNFS_LINK):
        nt = '@'
    elif (node_type == KERNFS_FILE):
        nt = '.'
    else:
        nt = '?{}'.format(node_type)
    return (name, nt)



# Decode the full path going up to parent. To prevent infinite loops,
# limit to 100
def kernfs_fullpath(kn):
    p = kn
    out = []
    count = 100
    while(p and count):
        name = p.name
        out.append(name)
        p = p.parent
        count -= 1
    out.reverse()
    if (count == 0):
        return "Bad kernfs_node"
    return "/".join(out)

if ( __name__ == '__main__'):
    root = readSymbol("sysfs_root")
    walk_kdir(root.kn)
