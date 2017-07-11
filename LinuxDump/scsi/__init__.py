# -*- coding: utf-8 -*-
# module LinuxDump.scsi
#
# --------------------------------------------------------------------
# (C) Copyright 2013-2017 Hewlett Packard Enterprise Development LP
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
from collections import (namedtuple, defaultdict, OrderedDict)
from LinuxDump.sysfs import *
from LinuxDump.kobjects import *
from LinuxDump.Time import j_delay


'''
Attached devices:
Host: scsi2 Channel: 03 Id: 00 Lun: 00
  Vendor: HP       Model: P420i            Rev: 3.54
  Type:   RAID                             ANSI  SCSI revision: 05
Host: scsi2 Channel: 00 Id: 00 Lun: 00
  Vendor: HP       Model: LOGICAL VOLUME   Rev: 3.54
  Type:   Direct-Access                    ANSI  SCSI revision: 05
'''

scsi_device_types = None
try:
    scsi_device_types = readSymbol("scsi_device_types")
except TypeError:
    loadModule("scsi_mod")
    loadModule("scsi_transport_fc")
    try:
        scsi_device_types = readSymbol("scsi_device_types")
    except TypeError:
        pass

def scsi_debuginfo_OK():
    if (scsi_device_types is None):
        print("+++Cannot find symbolic info for <scsi_device_types>\n"
            "   Put 'scsi_mod' debuginfo file into current directory\n"
            "   and then re-run the command adding --reload option")
        return False
    return True

# The following enums exists on all kernels we support
if (scsi_device_types is not None):
    enum_shost_state = EnumInfo("enum scsi_host_state")
    enum_st_state = EnumInfo("enum scsi_target_state")

try:
    _rq_atomic_flags = EnumInfo("enum rq_atomic_flags")
except TypeError:
    # RHEL5
    _rq_atomic_flags = {}

if ("REQ_ATOM_COMPLETE" in _rq_atomic_flags):
    _REQ_ATOM_COMPLETE = 1<< _rq_atomic_flags.REQ_ATOM_COMPLETE
else:
    _REQ_ATOM_COMPLETE = None
    
if ("REQ_ATOM_START" in _rq_atomic_flags):
    _REQ_ATOM_START = 1<< _rq_atomic_flags.REQ_ATOM_START
else:
    _REQ_ATOM_START = None

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


# Generic walk for all devices registered in 'struct class'
def class_for_each_device(_class):
    if (_class.hasField("p")):
        p = _class.p
        if (p.hasField("klist_devices")):
            klist_devices = p.klist_devices
        else:
            klist_devices = p.class_devices

    elif(_class.hasField("klist_devices")):
        klist_devices = _class.klist_devices
    else:
        # RHEL5
        for dev in ListHead(_class.children, "struct class_device").node:
            yield dev
        return

    for knode in klistAll(klist_devices):
        dev = container_of(knode, "struct device", "knode_class")
        yield dev

# ...........................................................................
#
# There are several ways to get lists of shosts/devices. We can get just
# Scsi_Host from 'shost_class', or we can get everything (hosts, devices,
# etc.) from 'scsi_bus_type'
#
# ...........................................................................

#
# get all Scsi_Host from 'shost_class'
#

def get_Scsi_Hosts_from_class():
    shost_class = readSymbol("shost_class")
    _rhel5 = shost_class.hasField("children")
    for dev in class_for_each_device(shost_class):
        if (_rhel5):
            yield container_of(dev, "struct Scsi_Host", "shost_classdev")
        else:
            #yield dev
            yield container_of(dev, "struct Scsi_Host", "shost_dev")

def scsi_device_lookup(shost):
    for a in ListHead(shost.__devices, "struct scsi_device").siblings:
        yield a

#
# Get all SCSI structures from 'scsi_bus_type"
#

scsi_types = ("scsi_host_type", "scsi_target_type", "scsi_dev_type")

def get_all_SCSI():
    _scsi_types_addrs = {sym2addr(n) : n for n in scsi_types}

    # Structures are different on different kernels
    scsi_bus_type = readSymbol("scsi_bus_type")
    try:
        klist_devices = scsi_bus_type.p.klist_devices
    except KeyError:
        klist_devices = scsi_bus_type.klist_devices

    out = defaultdict(list)
    for knode in klistAll(klist_devices):
        if (struct_exists("struct device_private")):
            dev = container_of(knode, "struct device_private", "knode_bus").device
            dev_type = _scsi_types_addrs.get(dev.type, None)
            if (dev.type is not None):
                #print(dev, dev_type)
                if (dev_type == "scsi_host_type"):
                    scsi_host = container_of(dev, "struct Scsi_Host", "shost_gendev")
                    out[dev_type].append(scsi_host)
                elif (dev_type == "scsi_dev_type"):
                    sdev = container_of(dev, "struct scsi_device", "sdev_gendev")
                    out[dev_type].append(sdev)
                    #print("      ---", sdev)
            else:
                out[dev_type].append(dev)
        else:
            # This is old code, is this correct for new kernels?
            dev = container_of(knode, "struct device", "knode_bus")
            sdev = container_of(dev, "struct scsi_device", "sdev_gendev")
            out["scsi_dev_type"].append(sdev)
            
    return out

# Get all SCSI devices. There are several ways of doing it, here we 
# loop on shosts and for each shost get its sdevices

@memoize_cond(CU_LIVE|CU_LOAD)
def get_SCSI_devices():
    out = []
    for shost in get_Scsi_Hosts_from_class():
        for sdev in scsi_device_lookup(shost):
            out.append(sdev)
    return out

# Return an ordered dict with some state info for Scsi_Host
def get_shost_states(shost):
    d = OrderedDict()
    for _a in ("last_reset", "host_busy", "host_failed", "host_eh_scheduled"):
        d[_a] = atomic_t(getattr(shost, _a))
    return d

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
    
    # Print shost_state
    shost_state = enum_shost_state.getnam(shost.shost_state)
    print("      shost_state={}".format(shost_state))
    priv = shost.hostdata
    hname = shost.hostt.name

    # Do we know the struct name for this host?
    if (hname.startswith("qla")):
        sname = 'struct scsi_qla_host'
    elif (hname == 'hpsa'):
        sname = 'struct ctlr_info'
    elif (hname == 'lpfc'):
        sname = 'struct lpfc_vport'
    elif (hname == 'bfa'):
        sname = 'struct bfad_im_port_s'
    elif ('pvscsi' in hname.lower()):
        sname = 'struct pvscsi_adapter'
    else:
        # We do not know the struct name
        sname = 'shost_priv(shost)'
    print("       hostt: {}   <{} {:#x}>".format(hname, sname, priv))
    
    do_driver_specific(shost)

# Print time info about request. This is duplicated in Dev, we should
# use the same subroutine
def request_timeinfo(req, jiffies = None):
    if (jiffies is None):
        jiffies = readSymbol("jiffies")
    ran_ago = j_delay(req.start_time, jiffies)
    # On RHEL5, 'struct request' does not have 'deadline' field
    try:
        if (req.deadline):
            deadline = float(req.deadline - jiffies)/HZ
            if (deadline > 0):
                fmt = "started {} ago, times out in {:5.2f}s"
            else:
                fmt = "started {} ago, timed out {:5.2f}s ago"
            return(fmt.format(ran_ago, abs(deadline)))
        else:
            return("started {} ago".format(ran_ago))
    except KeyError:
        return("{}started {} ago".format(ran_ago))


# get scsi_cmnd list from scsi_dev
def print_scsi_dev_cmnds(sdev, v=1):
    # Tghis subroutine does not work for old kernels (RHEL5)
    if (_REQ_ATOM_COMPLETE is None):
        return 0
    l = ListHead(sdev.request_queue.tag_busy_list)
    tagged_set = set(l)
    l_t = ListHead(sdev.request_queue.timeout_list)
    active_set = set(l_t)
    classified = 0
    jiffies = readSymbol("jiffies")

    for cmd in ListHead(sdev.cmd_list, "struct scsi_cmnd").list:
        flags = []
        request = cmd.request
        atomic_flags = request.atomic_flags
        if (_REQ_ATOM_COMPLETE is not None and (atomic_flags & _REQ_ATOM_COMPLETE)):
            flags.append('C')
        if (_REQ_ATOM_START is not None and (atomic_flags & _REQ_ATOM_START)):
            flags.append('S')

        if (long(cmd.request.timeout_list) in active_set):
            flags.append('T')
        if (long(cmd.request.queuelist) in tagged_set):
            flags.append('G')
        status = ''.join(flags)
        if (flags):
            classified += 1
        if (v < 2 and not flags):
            return classified

        print("    {:4} {} {}".format(status, cmd, request))
        print(" "*11,request_timeinfo(request, jiffies))
        print("\t     (jiffies - cmnd->jiffies_at_alloc)={}".format(
                        jiffies-cmd.jiffies_at_alloc))

        #print("           {:#x}  {}".format(cmd.serial_number, cmd.request.atomic_flags))
        
    return classified

# map "struct request" -> ("struct scsi_device", "struct scsi_cmnd")
def req2scsi_info():
    d = {}
    for sdev in get_SCSI_devices():
        for cmd in ListHead(sdev.cmd_list, "struct scsi_cmnd").list:
            d[cmd.request] = (sdev, cmd)
    return d

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


# *************************************************************************
#
#          Obsolete subroutines - used by old 'crashinfo --scsi' only
#
# *************************************************************************
# For v=0 list only different model/vendor combinations, how many a busy
# and different Scsi_Host
# For v=1 we additionally print all scsi devices that are busy/active
# For v=2 we print all scsi devices
def print_SCSI_devices(v=0):
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
                sbusy = ''
            else:
                sbusy = " busy={}".format(busy)
            if (devname or busy):
                print("devname={}{}".format(devname, sbusy))
            starget = scsi_target(sdev)
            is_fc = scsi_is_fc_rport(starget.dev.parent)
            st_state = enum_st_state.getnam(starget.state)
            #if (is_fc):
            print("  {} state = {}".format(starget, st_state))
            print("  {}".format(sdev.request_queue))
            
            print("  iorequest_cnt={}, iodone_cnt={}, diff={}".\
                  format(iorequest_cnt, iodone_cnt, cntdiff))
            classified = print_scsi_dev_cmnds(sdev, v)
            if (False and classified != busy):
                print("Mismatch", classified, busy)
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
