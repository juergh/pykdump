# -*- coding: utf-8 -*-
# module LinuxDump.Dev
#
# Time-stamp: <14/04/08 12:59:52 alexs>
#
# --------------------------------------------------------------------
# (C) Copyright 2013-2014 Hewlett-Packard Development Company, L.P.
#
# Author: Alex Sidorenko <asid@hp.com>
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

from __future__ import print_function

__doc__ = '''
This is a package providing generic access to SCSI stuff
'''

from pykdump.API import *
from collections import namedtuple, defaultdict
from LinuxDump.sysfs import *

'''
Attached devices:
Host: scsi2 Channel: 03 Id: 00 Lun: 00
  Vendor: HP       Model: P420i            Rev: 3.54
  Type:   RAID                             ANSI  SCSI revision: 05
Host: scsi2 Channel: 00 Id: 00 Lun: 00
  Vendor: HP       Model: LOGICAL VOLUME   Rev: 3.54
  Type:   Direct-Access                    ANSI  SCSI revision: 05
'''

# Iterate klist_devices
def klistAll(klist):
    try:
        return readSUListFromHead(klist.k_list, "n_node", "struct klist_node")
    except KeyError:
        return readSUListFromHead(klist.list, "n_node", "struct klist_node")

try:
    scsi_device_types = readSymbol("scsi_device_types")
except TypeError:
    loadModule("scsi_mod")
    try:
        scsi_device_types = readSymbol("scsi_device_types")
    except TypeError:
        print("+++Cannot find symbolic info for <scsi_device_types>")
        print("   Put 'scsi_mod' debuginfo file into current directory")
        sys.exit(0)

def scsi_device_type(t):
    if (t == 0x1e):
        return "Well-known LUN   "
    elif (t == 0x1f):
        return "No Device        "
    elif (t >= len(scsi_device_types)):
        return "Unknown          "
    return scsi_device_types[t]

# Get all SCSI devices

def get_SCSI_devices():
    scsi_bus_type = readSymbol("scsi_bus_type")
    # Structures are different on different kernels
    try:
        klist_devices = scsi_bus_type.p.klist_devices
    except KeyError:
        klist_devices = scsi_bus_type.klist_devices
    scsi_dev_type = sym2addr("scsi_dev_type")

    out = []
    for knode in klistAll(klist_devices):
        if (struct_exists("struct device_private")):
            dev = container_of(knode, "struct device_private", "knode_bus").device
            if (dev.type != scsi_dev_type):
                continue
        else:
            dev = container_of(knode, "struct device", "knode_bus")
        #print(dev)        
        out.append(container_of(dev, "struct scsi_device", "sdev_gendev"))
    return out
   
def print_SCSI_devices(v=0):   
    for sdev in get_SCSI_devices():
        if (v > 0):
            print('{:-^39}{:-^39}'.format(str(sdev)[8:-1], str(sdev.host)[8:-1]))
        #print(sdev, sdev.host)
        print("Host: scsi{} Channel: {:02} Id: {:02} Lun: {:02}".format(
            sdev.host.host_no, sdev.channel, sdev.id, sdev.lun))
        print("  Vendor: {:8} Model: {:16} Rev: {:4}".format(
            sdev.vendor[:8], sdev.model[:16], sdev.rev[:4]))
        print("  Type:   {}                ANSI  SCSI revision: {:02x}".format(
            scsi_device_type(sdev.type),  sdev.scsi_level - (sdev.scsi_level > 1)))

        if (v > 1):
            gendev = sdev.sdev_gendev
            sd = gendev2sd(gendev)
            print(sysfs_fullpath(sd))
            devname = blockdev_name(sd)
            busy = sdev.device_busy
            if (busy == 0):
                busy = ''
            else:
                busy = " busy={}".format(busy)
            if (devname or busy):
                print("devname={}{}".format(devname, busy))
    #print ("  ", scsi_dev.host.hostt.name)
