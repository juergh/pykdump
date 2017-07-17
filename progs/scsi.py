#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# --------------------------------------------------------------------
# (C) Copyright 2006-2017 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------

# Print info about SCSI subsystem


__version__ = "1.0.1"

from optparse import OptionParser

from collections import Counter, OrderedDict

from pykdump.API import *
from LinuxDump.scsi import *

from LinuxDump.kobjects import *


# Before doing anything else, check whether debuginfo is available!
if (not scsi_debuginfo_OK()):
    sys.exit(0)


# A subroutine that is used both for summaries and printing.
# Returns (busy, desc) for a give sdev
def _sdev_properties(sdev):
    busy = atomic_t(sdev.device_busy)
    _a = []
    _a.append("  Vendor: {:8} Model: {:16} Rev: {:4}".\
        format(sdev.vendor[:8], sdev.model[:16], sdev.rev[:4]))
    _a.append("  Type:   {}                ANSI  SCSI revision: {:02x}".\
        format(scsi_device_type(sdev.type),
                sdev.scsi_level - (sdev.scsi_level > 1)))
    s_descr = "\n".join(_a)
    return (busy, s_descr)

# By default we print busy devices only
def print_scsi_device(sdev, v = 0):
    #
    shost = sdev.host
    busy, s_descr = _sdev_properties(sdev)
    # iorequest_cnt-iodone_cnt
    iorequest_cnt = atomic_t(sdev.iorequest_cnt)
    iodone_cnt = atomic_t(sdev.iodone_cnt)
    cntdiff = sdev.iorequest_cnt.counter - sdev.iodone_cnt.counter
    print('{:-^39}{:-^39}'.format(str(sdev)[8:-1], str(shost)[8:-1]))
    print("Host: scsi{} Channel: {:02} Id: {:02} Lun: {:02}".format(
        shost.host_no, sdev.channel, sdev.id, sdev.lun))
    print(s_descr)
    gendev = sdev.sdev_gendev
    # SD is either 'sysfs_dirent' or 'kernfs_node'
    sd = gendev2sd(gendev)
    # is 'sd' non-NULL?
    if (sd):
        # strip /devices/ from the full sysfs path 
        print("    ", sysfs_fullpath(sd)[8:])
        devname = blockdev_name(sd)
    else:
        print("    kobj.name = {}, not in sysfs yet".format(gendev.kobj.name))
        devname = 'N/A'
    if (busy):
        print("     **busy={}".format(busy))
    if (devname):
        print("    devname={}".format(devname))
    if (v < 1):
        return

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
    return
    rport = starget_to_rport(starget)
    print("    ", shost.hostt)
    if (rport):
        print("   ", rport)
    

def print_iscsi_transports():
    lh = ListHead(sym2addr("iscsi_transports"), "struct iscsi_internal")
    for e in lh.list:
        print(addr2sym(e.iscsi_transport))

def print_transport_container(tc):
    ac = tc.ac
    print(tc)
    #for knode in klistAll(ac.containers):
    #    print(knode)

               

# Print SCSI Hosts only
def print_Scsi_Hosts(v=0, onlybusy=False):
    for shost in get_Scsi_Hosts_from_class():
        states = get_shost_states(shost)
        unusual = any(states.values())
        if (unusual or not onlybusy): 
            print_Scsi_Host(shost, v)

# This is a replacement of subroutine with a similar name in scsi/__init__.py
def print_Scsi_Devices(v=0, onlybusy=False):
    for shost in get_Scsi_Hosts_from_class():
        for sdev in scsi_device_lookup(shost):
            busy, s_descr = _sdev_properties(sdev)
            if (onlybusy and not busy):
                continue
            print_scsi_device(sdev, v)

# A highly-visible header
def bold_header(txt):
    print("*"*78)
    print("{:=^78}".format(txt))
    print("*"*78)

 # Print a summary
def print_summary(v=0, all = False):
    bold_header(" A Summary of SCSI Subsystem ")
    # Stats for scsi_hosts
    _shost_tot = 0
    shost_adapters = defaultdict(int)
    shost_flags = defaultdict(int)

    # Stats for devices
    _sdevs_tot = 0
    _sdevs_models = defaultdict(int)
    _sdevs_busy = 0
    for shost in get_Scsi_Hosts_from_class():
        _shost_tot += 1
        shost_adapters[shost.hostt.name] += 1
        for _a, val in get_shost_states(shost).items():
            if (val):
                shost_flags[_a] += 1
        # Iterate on sdevs for this host
        for sdev in scsi_device_lookup(shost):
            busy, s_descr = _sdev_properties(sdev)
            _sdevs_tot += 1
            if (busy):
                _sdevs_busy += 1
            _sdevs_models[s_descr] += 1
            

    print("  -------- SCSI hosts: {} --------".format(_shost_tot))
    print("    ... By Model ...")
    for k in sorted(shost_adapters.keys()):
        print("       {}:  {}".format(k, shost_adapters[k]))
    if (shost_flags):
        print("    ... By flags set ...")
        for k in sorted(shost_flags.keys()):
            print("       {}:  {}".format(k, shost_flags[k]))

    print("  -------- SCSI Devices: {} in total, {} of them are busy --------".\
        format(_sdevs_tot, _sdevs_busy))
    print("      .. Vendors/Types ..")
    for s_descr in sorted(_sdevs_models.keys()):
        print(s_descr, '\n')

    #  If we have specified verbose, print hosts/devices that are busy
    if (not v):
        return

    busyhosts = any(shost_flags.values())
    if (all or busyhosts):
        if (not all):
            bold_header(" Busy SCSI Hosts ")
        else:
            bold_header(" All SCSI Hosts ")
        print_Scsi_Hosts(v, not all)
    if (all or _sdevs_busy > 0):
        if (not all):
            bold_header(" Busy SCSI Devices ")
        else:
            bold_header(" All SCSI Devices ")

        print_Scsi_Devices(v, not all)
 
def print_others(d):
    for k in d:
        v = d[k]
        print(" {:=^50s}".format(k))
        if (k == "scsi_host_type"):
            continue
        if (v):
            print(" ===== {} =====".format(k))
            for o in v:
                #if (not o in scsi_devs):
                print("    {}".format(o))

op =  OptionParser()

op.add_option("-v", dest="Verbose", default = 0,
                action="count",
                help="verbose output")

op.add_option("--iscsi", dest="Iscsi", default = 0,
                action="store_true",
                help="Print iSCSI info")

op.add_option("--hosts", dest="Hosts", default = 0,
                action="store_true",
                help="Print SCSI Hosts info")

op.add_option("--devices", dest="Devs", default = 0,
                action="store_true",
                help="Print SCSI Devices info")

op.add_option("-a", "--all", dest="All", default = 0,
                action="store_true",
                help="Print info for all hosts/devs. By default, we print"
                    " busy only")

(o, args) = op.parse_args()


verbose = o.Verbose
all = o.All

if (o.Hosts):
    print_Scsi_Hosts(verbose, not all)
    sys.exit(0)

if (o.Devs):
    print_Scsi_Devices(verbose, not all)
    sys.exit(0)

if (o.Iscsi):
    print("Not implemented yet")
    sys.exit(0)


print_summary(verbose, all)

sys.exit(0)
