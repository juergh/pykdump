# module LinuxDump.trees
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2016 Hewlett Packard Enterprise Development LP
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
This is a package providing basic emulation of rb-trees and 
radix trees as used in Linux 
'''

__all__ = ["rb_first", "rb_next", "for_all_rbtree",
           "radix_tree_lookup_element", "walk_page_tree"]

from pykdump.API import *

# This is needed for speed optimization in some cases - should we
# make it visible via API.py?
from crash import mem2long

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

# ================ Radix trees etc. =============================

def ffs(x):
    """Returns the index, counting from 1, of the
    least significant set bit in `x`.
    """
    return (x&-x).bit_length()

#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)

#define RADIX_TREE_INDIRECT_PTR		1
 #struct radix_tree_node {
        #unsigned int    height;         /* Height from the bottom */
        #unsigned int    count;
        #struct rcu_head rcu_head;
        #void            *slots[RADIX_TREE_MAP_SIZE];
        #unsigned long   tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
 #};

# On newer kernels:
#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
#                                          RADIX_TREE_MAP_SHIFT))

#/* Height component in node->path */
#define RADIX_TREE_HEIGHT_SHIFT (RADIX_TREE_MAX_PATH + 1)
#define RADIX_TREE_HEIGHT_MASK  ((1UL << RADIX_TREE_HEIGHT_SHIFT) - 1)
# static unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH + 1]

RADIX_TREE_MAP_SIZE = None
RADIX_TREE_HEIGHT_MASK = None

_rnode = "struct radix_tree_node"
try:
    ti = getStructInfo(_rnode)["slots"].ti
    RADIX_TREE_MAP_SIZE = ti.dims[0]
    RADIX_TREE_MAP_MASK = RADIX_TREE_MAP_SIZE - 1
    RADIX_TREE_MAP_SHIFT = ffs(RADIX_TREE_MAP_SIZE) - 1
    RADIX_TREE_INDIRECT_PTR = 1
    height_to_maxindex = readSymbol("height_to_maxindex")
    # Are we on a kernel with 'radix_tree_node.path'?
    if (member_size(_rnode, "path") != -1):
            # Yes, we are
            RADIX_TREE_MAX_PATH = len(height_to_maxindex)-1
            RADIX_TREE_HEIGHT_SHIFT = RADIX_TREE_MAX_PATH + 1
            RADIX_TREE_HEIGHT_MASK = (1 << RADIX_TREE_HEIGHT_SHIFT) - 1
except:
    pass

#static void *radix_tree_lookup_element(struct radix_tree_root *root,
#                                 unsigned long index, int is_slot)

# We return (node, slot)
def radix_tree_lookup_element(root, index):
    if isinstance(root, (int, long)):
        root = readSU("struct radix_tree_root", root)
    #print(root, hexl(index))
    node = root.rnode
    if (not node):
        return (None, None)
    if (not radix_tree_is_indirect_ptr(node)):
        if (index > 0):
            return None
        return (node, root.rnode)
    #print("root node", node)
    node = readSU(_rnode, indirect_to_ptr(node))
    #print("indirect node", node)
    # height = node->path & RADIX_TREE_HEIGHT_MASK
    if (RADIX_TREE_HEIGHT_MASK):
        height = node.path & RADIX_TREE_HEIGHT_MASK
    else:
        # RHEL6
        height = node.height
    if (index > radix_tree_maxindex(height)):
        return (None, None)
    shift = (height-1) * RADIX_TREE_MAP_SHIFT
    #print("height={}. shift={}".format(height, shift))
    while(True):
        sindex = (index>>shift) & RADIX_TREE_MAP_MASK
        #print("sindex={}".format(sindex))
        _slot = node.slots[sindex]
        #print(hexl(_slot))
        node = readSU(_rnode, _slot)
        if (not node):
            return (None, None)
        shift -= RADIX_TREE_MAP_SHIFT
        height -= 1
        if (height == 0):
            break
    #return is_slot ? (void *)slot : indirect_to_ptr(node)
    return (indirect_to_ptr(node), _slot)

# static inline unsigned long radix_tree_maxindex(unsigned int height)
# {
#         return height_to_maxindex[height];
# }
def radix_tree_maxindex(height):
    return height_to_maxindex[height]
    
def radix_tree_is_indirect_ptr(addr):
    # return (int)((unsigned long)ptr & RADIX_TREE_INDIRECT_PTR);
    return (long(addr) & RADIX_TREE_INDIRECT_PTR)

def indirect_to_ptr(ptr):
    #return (void *)((unsigned long)ptr & ~RADIX_TREE_INDIRECT_PTR);
    return (long(ptr) & ~RADIX_TREE_INDIRECT_PTR)

def walk_page_tree(ptree, checkfordups = False):
    first_rnode = readSU(_rnode, indirect_to_ptr(ptree.rnode))
    if (not first_rnode):
        return []
    pheight = ptree.height
    _offset = member_offset(_rnode, "slots")
    _size = RADIX_TREE_MAP_SIZE * pointersize

    _addrs = set()
    def walk_radix_node(rnode, height):
        arr = mem2long(readmem(rnode+_offset, _size),
                       array=RADIX_TREE_MAP_SIZE)
        #for i, s in enumerate(rnode.slots):
        for i, s in enumerate(arr):
            if (not s):
                continue
            #node = readSU(_rnode, indirect_to_ptr(s))
            #print(i, height, hexl(s))
            if (height == 1):
                if (checkfordups):
                    if (s in _addrs):
                        print("duplicate {:#x}, {:#x}".format(rnode, s))
                        sys.exit(1)
                    _addrs.add(s)
                yield s
            else:
                #node = readSU(_rnode, s)
                for s1 in walk_radix_node(s, height-1):
                    yield s1
    return walk_radix_node(long(first_rnode), pheight)

# --- initialization
structSetAttr("struct rb_node", "rb_parent_color",
                  ["__rb_parent_color", "rb_parent_color"])
