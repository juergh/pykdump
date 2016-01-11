# -*- coding: utf-8 -*-
# module LinuxDump.scsi
#
# --------------------------------------------------------------------
# (C) Copyright 2013-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
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
from LinuxDump.kobjects import *


'''
Attached devices:
Host: scsi2 Channel: 03 Id: 00 Lun: 00
  Vendor: HP       Model: P420i            Rev: 3.54
  Type:   RAID                             ANSI  SCSI revision: 05
Host: scsi2 Channel: 00 Id: 00 Lun: 00
  Vendor: HP       Model: LOGICAL VOLUME   Rev: 3.54
  Type:   Direct-Access                    ANSI  SCSI revision: 05
'''


try:
    scsi_device_types = readSymbol("scsi_device_types")
except TypeError:
    loadModule("scsi_mod")
    loadModule("scsi_transport_fc")
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

if (symbol_exists("fc_rport_dev_release")):
    fc_rport_dev_release = sym2addr("fc_rport_dev_release")
else:
    fc_rport_dev_release = -1
# int scsi_is_fc_rport(const struct device *dev)
#{
#       return dev->release == fc_rport_dev_release;
# }
def scsi_is_fc_rport(dev):
    return (dev.release == fc_rport_dev_release)

#define dev_to_rport(d)                         \
#        container_of(d, struct fc_rport, dev)
def dev_to_rport(d):
    return container_of(d, "struct fc_rport", "dev")

# to_scsi_target(d): (d, struct scsi_target, dev)
def to_scsi_target(d):
    return container_of(d, "struct scsi_target", "dev")

# struct scsi_target *scsi_target(struct scsi_device *sdev) {
# return to_scsi_target(sdev->sdev_gendev.parent);
def scsi_target(sdev):
    return to_scsi_target(sdev.sdev_gendev.parent)

#define starget_to_rport(s)                     \
#        scsi_is_fc_rport(s->dev.parent) ? dev_to_rport(s->dev.parent) : NULL
def starget_to_rport(s):
    parent = s.dev.parent
    return dev_to_rport(parent) if scsi_is_fc_rport(parent) else None

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

# For v=0 list only different model/vendor combinations, how many a busy
# and different Scsi_Host
# For v=1 we additionally print all scsi devices that are busy/active
# For v=2 we print all scsi devices
def print_SCSI_devices(v=0):
    __enum_st_state = EnumInfo("enum scsi_target_state")
    shosts = set()
    n_busy = 0
    tot_devices = 0
    different_types = set()
    for sdev in get_SCSI_devices():
        tot_devices += 1
        shost = sdev.host
        shosts.add(shost)
        busy = atomic_t(sdev.device_busy)
        if (busy):
            n_busy += 1
        _a = []
        _a.append("  Vendor: {:8} Model: {:16} Rev: {:4}".\
            format(sdev.vendor[:8], sdev.model[:16], sdev.rev[:4]))
        _a.append("  Type:   {}                ANSI  SCSI revision: {:02x}".\
            format(scsi_device_type(sdev.type),
                   sdev.scsi_level - (sdev.scsi_level > 1)))
        s_descr = "\n".join(_a)
        different_types.add(s_descr)
        
        # iorequest_cnt-iodone_cnt
        iorequest_cnt = atomic_t(sdev.iorequest_cnt)
        iodone_cnt = atomic_t(sdev.iodone_cnt)
        cntdiff = sdev.iorequest_cnt.counter - sdev.iodone_cnt.counter
        if (v > 1 or (v > 0 and (busy))):
            print('{:-^39}{:-^39}'.format(str(sdev)[8:-1], str(shost)[8:-1]))
            print("Host: scsi{} Channel: {:02} Id: {:02} Lun: {:02}".format(
                shost.host_no, sdev.channel, sdev.id, sdev.lun))
            print(s_descr)

            gendev = sdev.sdev_gendev
            # SD is either 'sysfs_dirent' or 'kernfs_node'
            sd = gendev2sd(gendev)
            print(sysfs_fullpath(sd))
            devname = blockdev_name(sd)
            if (busy == 0):
                busy = ''
            else:
                busy = " busy={}".format(busy)
            if (devname or busy):
                print("devname={}{}".format(devname, busy))
            starget = scsi_target(sdev)
            is_fc = scsi_is_fc_rport(starget.dev.parent)
            st_state = __enum_st_state.getnam(starget.state)
            #if (is_fc):
            print("  {} state = {}".format(starget, st_state))
            
            print("  iorequest_cnt={}, iodone_cnt={}, diff={}".\
                  format(iorequest_cnt, iodone_cnt, cntdiff))
            continue
            rport = starget_to_rport(starget)
            print("    ", shost.hostt)
            if (rport):
                print("   ", rport)
            #print(scsi_target(sdev).dev.parent)
    if (different_types):
        print("\n{:=^70}".format(" Summary "))
        print("   -- {} SCSI Devices, {} Are Busy --".\
            format(tot_devices, n_busy))
        print("{:.^70}".format(" Vendors/Types "))
        for _a in different_types:
            print(_a)
            print()

    # Now print info about Shosts
    if (not shosts):
        return
    print("\n{:=^70}".format(" Scsi_Hosts"))
    for shost in sorted(shosts):
        print_Scsi_Host(shost)

    #print ("  ", scsi_dev.host.hostt.name)

def print_Scsi_Host(shost, v=0):
    hostt = shost.hostt
    print(" *scsi{}*  {}".format(shost.host_no, shost))
    print("     ", end='')
    sd = gendev2sd(shost.shost_gendev)
    print(sysfs_fullpath(sd))
    
    print("     ", end='')  
    for _a in ("last_reset", "host_busy", "host_failed", "host_eh_scheduled"):
        print(" {:s}={}".format(_a, atomic_t(getattr(shost, _a))), end='')
    print()
    do_driver_specific(shost)

import importlib
# Check whether there is an mportable submodule for this driver 
# and if yes, do extra processing
def do_driver_specific(shost):
    hostt = shost.hostt
    modname = hostt.name
    try:
        mod = importlib.import_module('.'+modname, package=__name__)
    except ImportError:
        return
    print("   -- Driver-specific Info {} --".format(hostt))
    mod.print_extra(shost)
