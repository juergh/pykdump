#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2016 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------

# To facilitate migration to Python-3, we use future statements/builtins
from __future__ import print_function

from pykdump.API import *

from LinuxDump.sysfs import *
from LinuxDump.kobjects import *

__all__ = ["print_PCI_devices", "print_PCI_resources"]

#static inline const char *pci_name(const struct pci_dev *pdev)
#{
        #return dev_name(&pdev->dev);
#}

def pci_name(pdev):
    return dev_name(pdev.dev)


# Get all PCI devices

def get_PCI_devices():
    pci_bus_type = readSymbol("pci_bus_type")
    # Structures are different on different kernels
    try:
        klist_devices = pci_bus_type.p.klist_devices
    except KeyError:
        klist_devices = pci_bus_type.klist_devices

    out = []
    for knode in klistAll(klist_devices):
        if (struct_exists("struct device_private")):
            dev = container_of(knode, "struct device_private", "knode_bus").device
        else:
            dev = container_of(knode, "struct device", "knode_bus")
        #print(dev)        
        out.append(container_of(dev, "struct pci_dev", "dev"))
    return out

def print_PCI_devices(v = 0):
    for pdev in get_PCI_devices():
        if (v > 0):
            print("----------", pdev, "-----------")
        #%02Xsc%02Xi%02x
        #(u8)(pci_dev->class >> 16), (u8)(pci_dev->class >> 8),
        #		       (u8)(pci_dev->class))
        name  = str(pci_name(pdev))
        # class is a reserved Python word
        pclass = (getattr(pdev, "class"))
        vendor = pdev.vendor
        device = pdev.device
        revision = pdev.revision
        print("{} {:04x}: {:04x}:{:04x} (rev {:02x})".\
              format(name[-7:], pclass >> 8,
                     vendor, device, revision))
 
#static struct resource *next_resource(struct resource *p, bool sibling_only)
#{
        #/* Caller wants to traverse through siblings only */
        #if (sibling_only)
                #return p->sibling;

        #if (p->child)
                #return p->child;
        #while (!p->sibling && p->parent)
                #p = p->parent;
        #return p->sibling;
#}

def next_resource(p):
    if (p.child):
        return p.child

    while (not p.sibling and p.parent):
        p = p.parent

    return p.sibling

_MAX_IORES_LEVEL = enumerator_value("MAX_IORES_LEVEL")

def walk_resource(root, v = 0):
    res = root.child
    #int width = root->end < 0x10000 ? 4 : 8;
    width = 4 if root.end < 0x10000 else 8
    
    fmt = "{:0>%dx}-{:0>%dx} : {}" % (width, width)
    n = 0
    while (True):
        #for(depth = 0, p = r; depth < MAX_IORES_LEVEL; depth++, p = p->parent)
        #        if (p->parent == root)
        #                break;
        p = res
        for depth in range(_MAX_IORES_LEVEL):
            if (p.parent == root):
                break
            p = p.parent
        padding = '  ' * depth
        
        #print(res)
        if (v):
            # Print structure addr
            print("\n{:-^40}".format(str(res)))
        print(padding, fmt.format(res.start, res.end, res.name), sep='')
        n += 1
        res =  next_resource(res)
        if (not res):
            break
    #print("\n {} total".format(n))

def print_PCI_resources(v = 0):
    for resname in ("iomem_resource", "ioport_resource"):
        try:
            root = readSymbol(resname)
        except:
            continue
        print("\n{:=^70}".format(resname))
        walk_resource(root, v)

if ( __name__ == '__main__'):
    import sys
    import argparse

    parser =  argparse.ArgumentParser()

    parser.add_argument("-v", dest="Verbose", default = 0,
                        action="count",
                        help="verbose output")

    o = parser.parse_args()

    print_PCI_devices(o.Verbose)

