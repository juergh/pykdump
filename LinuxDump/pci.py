#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------

# To facilitate migration to Python-3, we use future statements/builtins
from __future__ import print_function

from pykdump.API import *

from LinuxDump.sysfs import *
from LinuxDump.kobjects import *

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
    
if ( __name__ == '__main__'):
    import sys
    import argparse

    parser =  argparse.ArgumentParser()

    parser.add_argument("-v", dest="Verbose", default = 0,
                        action="count",
                        help="verbose output")

    o = parser.parse_args()

    print_PCI_devices(o.Verbose)

