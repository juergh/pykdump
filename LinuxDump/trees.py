# module LinuxDump.trees
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett Packard Enterprise Development LP
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

# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function

__doc__ = '''
This is a package providing basic emulation of rb-trees as used in Linux 
'''

from pykdump.API import *

# ---------  RB-trees as implemented in Linux kernel -------------

def rb_first(root):
    n = root.rb_node
    if (not n):
        return None
    while (n.rb_left):
        n = n.rb_left
    return n

#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
# struct rb_node {
#     long unsigned int rb_parent_color;
#     struct rb_node *rb_right;
#     struct rb_node *rb_left;
# }


# r is rb_node
def rb_parent(r):
    return readSU("struct rb_node", (r.rb_parent_color & ~3))
    


def rb_next(node):
    if (rb_parent(node) == node):
        return None

    # If we have a right-hand child, go down and then left as far
    # as we can.
    if (node.rb_right):
        node = node.rb_right
        while (node.rb_left):
            node = node.rb_left
        return node

    while(True):
        parent = rb_parent(node)
        if (not parent or node != parent.rb_right):
            break
        node = parent

    return parent
                

# Iterate though rb-tree starting from its root

def for_all_rbtree(root, sname = None, smember = None):
    node = rb_first(root)
    while (node):
        if (sname):
            yield  container_of(node, sname, smember)
        else:
            yield node
        node = rb_next(node)


# --- initialization
structSetAttr("struct rb_node", "rb_parent_color",
                  ["__rb_parent_color", "rb_parent_color"])
