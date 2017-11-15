# -*- coding: utf-8 -*-
# module LinuxDump.Dev
#
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2017 Hewlett Packard Enterprise Development LP
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

__doc__ = '''
This is a package providing generic access to block devices
'''

from pykdump.API import *
from LinuxDump.percpu import percpu_ptr, get_cpu_var
from LinuxDump.Time import j_delay
from .scsi import req2scsi_info, scsi_debuginfo_OK

import re
from collections import namedtuple, defaultdict, Counter

import textwrap
from textwrap import TextWrapper

# Pretty-printing
class listTextWrapper(textwrap.TextWrapper):
    #wordsep_simple_re = re.compile(r'(,)')
    wordsep_re =  re.compile(r'(,)')


def list_fill(text, width=70, **kwargs):
    """Fill a single paragraph of text, returning a new string.

    Reformat the single paragraph in 'text' to fit in lines of no more
    than 'width' columns, and return a new string containing the entire
    wrapped paragraph.  As with wrap(), tabs are expanded and other
    whitespace characters converted to space.  See TextWrapper class for
    available keyword args to customize wrapping behaviour.
    """
    w = listTextWrapper(width=width, **kwargs)
    return w.fill(text)


# To save space, we print <sname addr> instead of <struct sname addr>
def stripStructName(sname):
    return '<' + str(sname)[8:]



# ***************************************************************************
#
#      Block Devices and Gendisks code
#
# ***************************************************************************

# Decode dev_t
# major, minor = decode_devt(dev)
def decode_devt(dev):
    if (dev >>16):
        # New-style
        major = dev >> 20
        minor = dev ^ (major<<20)
    else:
        # Old-style
        major = dev >>8
        minor = dev & 0xff
    return (int(major), int(minor))


# Declare global tables - to be used explicitly in this module only
_bdev_map = defaultdict(list)
_major_names = {} # Name indexed by major
_all_bdevs = defaultdict(list) # 'struct block_device' lists indexed by major

@memoize_cond(CU_LIVE|CU_PYMOD)
def get_blkdev_tables():
    _bdev_map.clear()
    _major_names.clear()
    _all_bdevs.clear()
    if (symbol_exists("bdev_map")):
        for probe in readSymbol("bdev_map").probes:
            while(probe):
                gd = readSU("struct gendisk", probe.data)
                if (gd and gd.fops):
                    #fops = "<{}>".format(addr2sym(gd.fops))
                    _bdev_map[gd.major].append((gd.first_minor, gd))
                probe = probe.next
        # Sort on first_minor
        for major in _bdev_map.keys():
            _bdev_map[major] = [s[1] for s in sorted(_bdev_map[major])]



    if (symbol_exists('major_names')):
        for bmn in readSymbol('major_names'):
            # struct blk_major_name *
            while(bmn):
                _major_names[bmn.major] = bmn.name
                bmn = bmn.next


    if (symbol_exists('all_bdevs')):
        for bd in readSUListFromHead(sym2addr('all_bdevs'), 
                                    'bd_list', 'struct block_device'):
            major, minor = decode_devt(bd.bd_dev)
            _all_bdevs[major].append((minor, bd))
        # Sort by minor
        for major in _all_bdevs.keys():
            _all_bdevs[major] = sorted(_all_bdevs[major])


# Get minor/gendisk/block_device for a given major
def get_bd_gd(major):
    count_all = 0
    
    out = []
    # For devices in this table, we know all three things:
    # minor, gendisk,blockdevice
    for minor, bd in _all_bdevs[major]:
        gd = bd.bd_disk
        #print(gd)
        if (gd):
            count_all += 1
            out.append((minor, bd, gd))
            continue

    if (not count_all):
        # Here we can get gendisk but not blockdevice
        for gd in _bdev_map[major]:
            out.append((None, None, gd))
            continue
            bdops = addr2sym(gd.fops)
    return out

def print_blkdevs(v=0):
    get_blkdev_tables()
    # Print 
    for major in sorted(_major_names.keys()):
        
        print('{:3}  {:16}'.format(major, _major_names[major]),end='')
      
        out = get_bd_gd(major)
             
        if (v == 0):
            if (len(out)):
                gd0 = out[0][2]
                bdops = addr2sym(gd0.fops)
                print(" {} fops={}".format(gd0, bdops))
            else:
                print("")
        elif (v >= 1):
            print("")
            for (minor, bd, gd) in out:
                bd_queue = get_requestqueue(bd, gd)
                if (minor == None):
                    # gendisk only - both minor and bd are None
                    print('    first_minor={:<4d}   {} {}'.format(gd.first_minor, 
                                                            gd.disk_name, gd))
                else:
                    try:
                        partno = str(bd.bd_part.partno)
                        if (partno == '0'):
                            partno = ''
                    except:
                        partno = ''
                    gd_name = gd.disk_name + partno
                    print('   {:3d} {:5} {} {}'.format(minor, gd_name,
                                                    stripStructName(bd),
                                                    stripStructName(gd)))
                                  
                if (v > 0 and bd_queue):
                    # Print request queue length (if they are available)
                    #
                    # request queue can be either bd.bd_queue or 
                    # bd.bd_disk.queue but if we know gendisk we can just do
                    # gd.queue
                        
                    lq, in_flight, count = check_request_queue(bd_queue)

                    if (v > 1 or (lq or in_flight or count)):
                        print ("         {}  Len={} in_flight={} count={}".format(
                            bd_queue, lq, in_flight, count))

                      
        continue
                
        print (list_fill(str(_bdev_map[major]), initial_indent=' '*3,
                            subsequent_indent=' ' * 5))
        print (list_fill(str(_all_bdevs[major]), initial_indent=' '*3,
                            subsequent_indent=' ' * 5))

# --- OLD ---

class BlkDev(object):
    def __init__(self, major, name, ops, bdevs):
        minors = sorted([m for m, bds in bdevs])
        self.major = major
        self.minors = minors
        self.name = name
        self.ops = ops
        self.opsname = addr2sym(self.ops)
        self.bdevs = bdevs
    def __str__(self):
        #prn = StringIO()
        return " %3d  %-11s   %x  <%s>" % \
              (self.major, self.name, self.ops, self.opsname)
    def shortstr(self):
        return "driver=%s, bdops=<%s>" % (self.name, self.opsname)



# This function returns a dictionary of (name, gendisk) keyed
# by major

@memoize_cond(CU_LIVE|CU_PYMOD)
def get_blkdevs():
    if (symbol_exists('all_bdevs')):
        return get_blkdevs_v2()
    else:
        return get_blkdevs_v1()

def get_blkdevs_v1():
    # static struct list_head bdev_hashtable[HASH_SIZE];
    # and heads are embedded in 'struct block_device'
    
    m_bdevs = {}
    out_bddev = {}      # a dict with bd_dev key
    for h in readSymbol("bdev_hashtable"):
        for s in readSUListFromHead(h, 'bd_hash',
             'struct block_device'):
            # We have one block_device structure per minor
            major, minor =  decode_devt(s.bd_dev)
            out_bddev[s.bd_dev] = s
            m_bdevs.setdefault(major, []).append((minor, s))
    
    pa = readSymbol('blkdevs')
    out = {}
    for major, s in enumerate(pa):
        if (not major in m_bdevs):
            continue
        bi = BlkDev(major, s.name, s.bdops, m_bdevs[major])
        out[major] = bi
    
    return out, out_bddev


def get_blkdevs_v2():
    # We want to group info per major, i.e. for each major we have
    # a list of all 'struct block_device' sorted by minor
    m_bdevs = defaultdict(list)
    out_bddev = {}      # a dict with bd_dev key
    for s in readSUListFromHead(sym2addr('all_bdevs'), 
           'bd_list', 'struct block_device'):
        major, minor =  decode_devt(s.bd_dev)
        out_bddev[s.bd_dev] = s
        m_bdevs[major].append((minor, s))
  
    # When we register a device, it can grab several major
    # numbers just in case - even if it does not need them
    # right now. See e.g. drivers/scsi/sd.c 
    # 'crash' prints all of them - but I think this is
    # a waste of time. For all practical purposes we are always
    # interested only in those devices that are physically
    # present (i.e. are in 'all_bdevs')
    out = {}
    for addr in readSymbol('major_names'):
        while(addr):
            s = Deref(addr)
            addr = s.next
            major = s.major
            if (not major in m_bdevs):
                #print ("major", major)
                continue
            bd = m_bdevs[major]
            # There are cases when device is registered but bd_disk=0
            # E.g. this happens when CD is not present in CD-ROM
            bd_disk = bd[0][1].bd_disk
            if (bd_disk):
               bdops = bd_disk.fops
               #print bd_disk.kobj.name
            else:
                bdops = 0
            out[major] = BlkDev(major, s.name, bdops, bd)
    return out, out_bddev

def old_print_blkdevs(v = 0):
    out, out_bddev = get_blkdevs()
    majors = sorted(out.keys())
    sep = '-' * 70
    if (v):
        print (sep)
    if (v > 1):
        devs = sorted(out_bddev.keys())
        for dev in devs:
            bd = out_bddev[dev]
            print (hexl(dev), bd)
            bd_holder = bd.bd_holder
            print (" ", bd.bd_openers, hexl(bd_holder))
            if (bd_holder):
                si = exec_gdb_command("x/i 0x%x" % bd_holder).rstrip()
                ss = exec_gdb_command("x/s 0x%x" % bd_holder).rstrip()
                print ("  ", si)
                print ("  ", ss)
    
    for major in majors:
        bi = out[major]
        #name, ops, bdevs = out[major]
        minors = bi.minors
        ops= bi.ops
        bdevs = bi.bdevs
        print (" %3d    %-14s   %x  <%s>" % \
              (major, bi.name, ops, addr2sym(ops)))
        if (v):
           print (textwrap.fill("\tMinors:" + str(minors), initial_indent=' ',
                  subsequent_indent=' ' *9))

           print ("\t", bdevs[0][1])

        if (v):
           print (sep)


# ================= Device-Mapper =======================
#
# To use these functions, you need a debuggable dm-mod loaded

#struct hash_cell {
    #struct list_head name_list;
    #struct list_head uuid_list;
    #char *name;
    #char *uuid;
    #struct mapped_device *md;
    #struct dm_table *new_map;
#}

def print_dm_devices(verbose = 0):
    sn = "struct dm_table"
    # Check whether this struct info is present
    if (not struct_exists(sn)):
        loadModule("dm_mod")
    if (not struct_exists(sn)):
        print ("To decode DeviceMapper structures, you need a debuggable dm_mod")
        return
    # Some kernels have multiple 'struct dm_table" definitions, we need
    # the correct one!
    # See https://www.redhat.com/archives/dm-devel/2015-December/msg00045.html
    if (symbol_exists("dm_table_create")):
        exec_crash_command("set scope dm_table_create")
    purge_typeinfo(sn)      # Purge old definitions
    nameb = readSymbol("_name_buckets")
    out = []
    off = member_offset("struct hash_cell", "name_list")
    # On older kernels, struct mapped_device has 'struct dm_table *map' field
    # On newer ones, it is just 'void *map'
    for b in nameb:
        for a in readListByHead(b):
            hc = readSU("struct hash_cell", a - off)
            dm_table = readSU('struct dm_table', hc.md.map)
            out.append((hc.md.disk.first_minor, hc.name, dm_table))
    
    out.sort()      # sort on minor
    print (" ========== Devicemapper devices ============")
    for minor, name, dm in out:
        if (verbose):
           print ('-'*70)
        print ("%-40s  minor=%d" % (name, minor))
        if (verbose):
            print ("  ", dm)
            decode_dm_table(dm)

# Decode struct dm_table
#  list entries are embedded in
#struct dm_dev {
    #struct list_head list;
    #atomic_t count;
    #int mode;
    #struct block_device *bdev;
    #char name[16];
#}

def decode_dm_table(dm, verbose = 0):
    def round4k(s):
        return s/4096*4096
    devices = dm.devices   # This points to 'list' field in dm_dev
    # On newer kernels (e.g. 2.6.31)
    #
    # struct dm_dev_internal {
    #   struct list_head list;
    #   atomic_t count;
    #   struct dm_dev dm_dev;
    # }
    
    # And on later RHEL6 we have a pointer instead:
    # struct dm_dev *dm_dev;
    
    def get_dm_dev(devices):
        return PY_select(
            'ListHead(devices, "struct dm_dev_internal").list',
            'ListHead(devices, "struct dm_dev").list'
            )

    mtable, out_bddev = get_blkdevs()
    num_targets = dm.num_targets
    print (" -- %d targets" % num_targets)
    targets = dm.targets
    for nt in range(num_targets):
        target = targets + nt
        ttype = target.type
        t_begin = target.begin
        t_len = target.len
        t_end = t_begin + t_len - 1
        
        print ("  %d" % nt, target, ttype.name)
        print ("       | logical  sectors %d->%d" %(t_begin, t_end))
        if (ttype.name == "linear"):
            lc = readSU("struct linear_c", target.private)
            lc_begin = lc.start
            lc_end = lc.start + t_len -1
            print ("       | physical sectors %d->%d" %(lc_begin, lc_end))
            print ("       |    device used", lc.dev)
    
    print (" -- Block Devices Used By This Mapping")
    for o in get_dm_dev(devices):
        dmdev = PY_select(
            "o.dm_dev",
            "o"
            )
        major, minor = decode_devt(dmdev.bdev.bd_dev)
        print ("     ", dmdev, "major=%-3d minor=%-3d" % (major, minor))
        print ("\t   ", mtable[major].shortstr())



# ================ gendisk stuff =============================
# Get the list of (dev, gendisk) sorted by dev

def get_gendisks():
    out = []
    # We do not process other gets yet (e.g. ata_probe)
    good_gets = sym2alladdr("exact_match")
    for pm in readSymbol("bdev_map").probes:
        for p in readStructNext(Deref(pm), "next"):
            data = p.data
            dev = p.dev
            if (data and long(p.get) in good_gets):
                #print '--', hexl(dev), p
                gd = readSU("struct gendisk", data)
                out.append((dev, gd))

    out.sort()
    return out

# Print disk statistics
def print_disk_stats(gd):
    ptr = gd.dkstats
    # gd.dkstats is a per-cpu pointer
    for cpu in range(sys_info.CPUS):
        pcpu = percpu_ptr(ptr, cpu)
        print ("  ", cpu, pcpu)
        #printObject(pcpu)
        
        
# Print gendisk structures with some checking.
# If v=0, print errors only
__re_good_diskname = re.compile(r'^[-\w:/.]+$')
def print_gendisk(v = 1):
    try:
        gdlist = get_gendisks()
    except TypeError:
        if (v):
            print ("print_gendisk is not implemented for this kernel yet")
        return
    # To get block_device based on dev_t
    once = TrueOnce()
    dummy, bd_devs = get_blkdevs()
    #
    for dev, gd in gdlist:
        if (v > 1):
            print ('#' * 50)
        disk_name = gd.disk_name
        # Check whether name is alphanum
        if (not __re_good_diskname.match(disk_name)):
            disk_name = '???'
            if (once):
                pylog.error("Corrupted all_bdevs list")
            continue
        #kname = gd.kobj.name
        openname = None
        
        try:
            owner = gd.fops.owner
            badfops = False
        except crash.error:
            badfops = True
        
        try:
            openptr = gd.fops.open
            if (openptr):
                openname = addr2sym(openptr)
        except (IndexError, crash.error):
            openname = "n/a"
            badfops = True

        if (badfops):
            pylog.error(gd, "corrupted fops, disk_name=%s dev=0x%x"% \
                   (disk_name, dev))
            continue

        if (v):
           print  ("  %12s dev=0x%x" % (disk_name, dev), gd, openname)
        outparts = []
        # < 2.6.28
        # struct hd_struct **part;
        # 2.6.28
        #    struct disk_part_tbl *part_tbl;
        #    struct hd_struct part0;
        # and
        # struct disk_part_tbl {
        #     struct rcu_head rcu_head;
        #     int len;
        #     struct hd_struct *part[];
        #  };
        try:
            np = gd.part_tbl.len
            tbl =  gd.part_tbl.part
        except KeyError:
            np = gd.minors - 1
            tbl = gd.part
        for i in range(np):
            #print("tbl", repr(tbl))
            hd = tbl[i]
            #print("hd", repr(hd))
            try:
                if (hd and hd.Deref.nr_sects):
                    if (v):
                        print ("\t\t", i, Deref(hd))
            except crash.error:
                outparts.append(i)
                if (v):
                    pylog.error("corrupted", Deref(hd))
        if (outparts):
            pylog.error(gd, "corrupted part list", outparts)
        
        if (v < 2):
            continue


# ***************************************************************************
#
#      Requests and request queues code
#
# ***************************************************************************

try:
# Decode cmd_flags using "enum rq_flag_bits"  from include/linux/blk_types.h
# Bits are defined as 1<<enumval

    __RQ_FLAG_bits = EnumInfo("enum rq_flag_bits")
    # Convert it to proper bits
    __RQ_FLAG_realbits = {k[6:]: 1<<v for k,v in __RQ_FLAG_bits.items()}
except TypeError:
    # Old kernels
    __RQ_FLAG_realbits = {}
    for bit, s in enumerate(readSymbol("rq_flags")):
        __RQ_FLAG_realbits[str(s)[4:]] = 1<<bit

# WRITE can be both __REQ_RW and __REQ_WRITE
if ("WRITE" in __RQ_FLAG_realbits):    
    def is_request_WRITE(rq):
        return (rq.Flags & __RQ_FLAG_realbits["WRITE"])
else:
    def is_request_WRITE(rq):
        return (rq.Flags & __RQ_FLAG_realbits["RW"])

def decode_cmd_flags(f):
    return dbits2str(f, __RQ_FLAG_realbits)

def is_request_STARTED(rq):
    return (rq.Flags & __RQ_FLAG_realbits["STARTED"])



structSetAttr("struct request", "Flags", ["flags", "cmd_flags"])


def XXX_get_requestqueue(bd, gd):
    bd_queue = None
    if (not bd):
        try:
            bd_queue = gd.queue
        except:
            pass
    else:
        try:
            if (bd.hasField("bd_queue")):
                bd_queue = bd.bd_queue
            else:
                bd_queue = bd.bd_disk.queue 
        except:
            pass
    return bd_queue

def get_requestqueue(bd, gd):
    bd_queue = PY_select(
        "gd.queue",
        "bd.bd_queue",
        "bd.bd_disk.queue")
    return bd_queue

def get_request_queues():
    get_blkdev_tables()
    qlist = {}
    for major in sorted(_major_names.keys()):
        for minor, bd, gd in get_bd_gd(major):
            bd_queue = get_requestqueue(bd, gd)
            qlist[bd_queue] = (bd, gd)
    return qlist

# Check whether there is anything interesting on this request_queue
def check_request_queue(rqueue):
    lq = len(ListHead(rqueue.queue_head))
    if rqueue.hasField("rqs"):
        count = rqueue.rqs[0] + rqueue.rqs[1]
    elif rqueue.hasField("nr_rqs"):
        count = rqueue.nr_rqs[0] + rqueue.nr_rqs[1]
    elif (rqueue.hasField("rq")):
        rq_list = rqueue.rq
        count = rq_list.count[0] + rq_list.count[1]
    else:
        count = None
    try:
        in_flight = rqueue.in_flight[0] + rqueue.in_flight[1]
    except TypeError:
        in_flight = rqueue.in_flight
    
    return(lq, in_flight, count)

# ................................................................
#define RQ_INACTIVE             (-1)
#define RQ_ACTIVE               1
#define RQ_SCSI_BUSY            0xffff
#define RQ_SCSI_DONE            0xfffe
#define RQ_SCSI_DISCONNECTING   0xffe0

# Sanity check. We retirn None if everything's fine, 
# otherwise a string withmoer details
def is_request_BAD(rq):
    if (not rq.bio):
        return "rq.bio = NULL"

    # Can we dereference bio?
    try:
        readS64(rq.bio)
    except crash.error:
        return "cannot dereference rq.bio"
    
    # Is cpu within bounds:
    try:
        cpu = rq.cpu
        if (cpu < 0 or cpu >10000):
            return "bad CPU number"
    except:
        pass
    
    # Do we have rq_status? If yes, is it reasonable?
    try:
        rq_status = rq.rq_status
        if (rq_status <= 0 or not rq_status in (1, 0xffff, 0xfffe, 0xffe0)):
            return "bad rq_status"
    except KeyError:
        pass
    
    # If cmd_len exists but is too high, this is not a 
    # valid structure
    try:
        if (rq.cmd_len > 16):
            return "rq.cmd_len > 16"   
        rq_disk = rq.rq_disk
        if (not rq_disk):
            return "bad rq.rq_disk"
        # Is major reasonable?
        if (rq_disk.major < 0 or rq_disk.major > 10000):
            return "bad rq.rq_disk.major"
    except KeyError:
        pass
    except crash.error:
        return "Corrupted rq"
    
    if (not rq.q):
        return "rq.q=0"
    if (long(rq.q)%4 != 0):
        return "rq.q unaligned"
    try:
        # Try to dereference the queue
        head = rq.q.queue_head.next
    except crash.error:
        return "bogus rq.q"
  
    return None
    
# On different kernels we have different fields. As we mainly use this
# function on pointers from slab/allocated, there can be bogus pointers
# Do not print them


def decode_request(rq, v = 0, reqscsmap = {}):
    out = []
    # Do not decode 'bad' structures
    ifbad = is_request_BAD(rq)
    if (ifbad):
        return "   {} BAD: {}".format(str(rq), ifbad)
    else:
        out.append("    " + str(rq))
    # Do we have rq_status? If yes, is it reasonable?
    try:
        rq_status = rq.rq_status
        out.append("\trq_status=0x%x" % rq_status)
    except KeyError:
        pass
    try:
        rq_dev = rq.rq_dev
        (major, minor) = decode_devt(rq_dev)
        out.append("\trq_dev=0x%x major=%d minor=%d" % \
           (rq.rq_dev, major, minor))
    except KeyError:
        pass
    

    try:
        rq_disk = rq.rq_disk
        out.append("\tdisk_name=%s major=%d" % \
           (rq_disk.disk_name,rq_disk.major))
    except KeyError:
        pass
    
    try:
        q = rq.q
    except KeyError:
        pass
    try:
        cmd_flags = rq.cmd_flags
        ref_count = rq.ref_count
        atomic_flags  = rq.atomic_flags
        special = rq.special
        if (v > 1):
            out.append("        cmd_flags=0x%x, ref_count=%d" %\
            (cmd_flags, ref_count))
            if (atomic_flags == 1):
                out.append("        atomic_flags=0x%x" % atomic_flags)
            if (special):
                scsi = readSU("struct scsi_cmnd", special)
                out.append("        special=0x%x %s" % (special, str(scsi)))

    except KeyError:
        pass
    
    if (v > 1):
        out.append(decode_cmd_flags(rq.Flags))
    jiffies = readSymbol("jiffies")
    ran_ago = j_delay(rq.start_time, jiffies)

    # On RHEL5, 'struct request' does not have 'deadline' field
    try:
        if (rq.deadline):
            deadline = float(rq.deadline - jiffies)/HZ
            if (deadline > 0):
                fmt = "\t  started {} ago, times out in {:5.2f}s"
            else:
                fmt = "\t  started {} ago, timed out {:5.2f}s ago"
            out.append(fmt.format(ran_ago, abs(deadline)))
        else:
            out.append("\t  started {} ago".format(ran_ago))
    except KeyError:
        out.append("\t  started {} ago".format(ran_ago))

    if (rq in reqscsmap):
        sdev, cmd = reqscsmap[rq]
        out.append("\t  {}  {}".format(sdev.shortStr(), cmd.shortStr()))
        out.append("\t  (jiffies - cmnd->jiffies_at_alloc)={}".format(
                        jiffies-cmd.jiffies_at_alloc))
    
    return "\n".join(out)    
# ********************************************************************

# Print stuff from block/blk-softirq.c
def print_blk_cpu_done(v = 0):
    if (not symbol_exists("blk_cpu_done")):
        # This is an old kernel (e.g. RHEL4)
        return
    total = 0
    out = []
    for cpu, val in enumerate(get_cpu_var("blk_cpu_done")):
        lh = ListHead(val, "struct request")
        if (not len(lh)):
            continue
        total += len(lh)
        if (v > 0):
            out.append("   CPU={} Len={}".format(cpu, len(lh)))
        if (v > 1):
            for r in lh.csd:
                out.append("   {}".format(str(r)))
    if (total or v >= 0):
        print (" -- Requests on blk_cpu_done:    Count={}".format(total))
        if (v > 0 and total):
            print("\n".join(out))
    return total

# Analyze 'request_queue' lists. Print the results and return t_count
# (to compare it with heuristics from slabs)

def print_request_queues(v=0):
    qlist = get_request_queues()

    t_in = t_count = 0
    out = []
    hl = '-'*70
    for bd_queue, (bd, gd) in qlist.items():
        lq, in_flight, count = check_request_queue(bd_queue)
        if (lq or in_flight or count):
            t_in += in_flight
            t_count += count
            oa = []
            if (v):
                oa.append("{:<16s} count={:<4d} in_flight={:<4d}".\
                    format(gd.disk_name, count, in_flight))
                if (v > 1):
                    oa.append("  {}  {}".format(str(bd_queue), str(gd)))
                    oa.append(hl)
                out.append("\n".join(oa))
  
    # If v=-1 and we did not found any outstanding requests, don't print anything
    lout = len(out)
    if (v < 0 and lout == 0):
        return 0
    print(" -- Request Queues Analysis:     Count={}, in_flight={}".format(t_count, t_in))
    if (lout):
        if (v > 1):
            print(hl)
        if (v > 0):
            print("\n".join(sorted(out)))
    return t_count

# Heuristcis: find requests allocated on SLAB
def print_request_slab(v):    
    # Requests allocated on SLAB
    from LinuxDump.Slab import get_slab_addrs
    # WARNING: on some kernels (e.g. Ubuntu/Hardy, 2.6.24)
    # blkdev_requests is mapped to a general slab.
    # E.g. when struct request has size 188, it goes into "kmalloc-192"
    # 
    try:
        name = readSymbol("request_cachep").name
    except:
        name = "blkdev_requests"
    try:
        (alloc, free) = get_slab_addrs(name)
    except crash.error as val:
        print (val)
        return
    rqlist = []
    jiffies = readSymbol("jiffies")
    f_started = 0
    f_write = 0
    cmd_stats = Counter()
    for rqa in alloc:
        rq = readSU("struct request", rqa)
        #bad = is_request_BAD(rq)
        #print(rq, hexl(rq.Flags), bad)
        if (is_request_BAD(rq)):
            continue
        if (is_request_STARTED(rq)):
            f_started += 1
        if (is_request_WRITE(rq)):
            f_write += 1
        ran_ago = (jiffies - rq.start_time) & INT_MASK
 
        cmd_stats[decode_cmd_flags(rq.Flags)] += 1
        rqlist.append((ran_ago, rq))
    
    # Sort by ran ago - newest first
    rqlist = sorted(rqlist)
    totreq = len(rqlist)

    if (totreq or v >= 0):
        print(" -- Requests from SLAB Analysis: Count={}, STARTED={} WRITE={}".\
            format(totreq, f_started, f_write))
    if (totreq):
        newest = rqlist[0][0]
        oldest = rqlist[-1][0]

        print("      -- Since started: newest {:8.2f}s,  oldest {:8.2f}s".\
            format(float(newest)/HZ, float(oldest)/HZ))


        if (v < 0):
            pylog.warning("there are outstanding blk_dev requests")
    
    if (v < 1):
        return
    if (scsi_debuginfo_OK()):
        reqscsmap = req2scsi_info()
    else:
        reqscsmap = {}
 
    for ts, rq in rqlist:
        try:
            rqs = decode_request(rq, v, reqscsmap)
        except crash.error:
            rqs = str(rq) + " is BAD"
        print(rqs)
    # Print stats for cmd flags
    if (totreq):
        print ("  -- Summary of flags combinations")
        out = []
        for k, val in cmd_stats.items():
            out.append("{:4d} {}".format(val, k))
        # Now sort and print
        for s in sorted(out):
            print(s)

    return totreq

 
# Device inode to block_device
# static inline struct bdev_inode *BDEV_I(struct inode *inode)
# {
#         return container_of(inode, struct bdev_inode, vfs_inode);
# }
# 
# inline struct block_device *I_BDEV(struct inode *inode)
# {
#         return &BDEV_I(inode)->bdev;
# }


def BDEV_I(inode):
    return container_of(inode, 'struct bdev_inode', 'vfs_inode')

def I_BDEV(inode):
    return BDEV_I(inode).bdev
