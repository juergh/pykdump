# --------------------------------------------------------------------
# (C) Copyright 2006-2014 Hewlett-Packard Development Company, L.P.
# (C) Copyright 2014-2015 Red Hat, Inc.
#
# Author: David Jeffery
#
# Contributor:
# - Milan P. Gandhi
#      Added/updated following options:
#       -d     show the scsi devices on system
#              this option is similar to 'shost -d'
#       -s     show Scsi_Host info
#       -T     show scsi targets through which 
#              scsi devices are connected
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

__version__ = "0.0.2"

from pykdump.API import *

from LinuxDump.scsi import *

from pykdump.wrapcrash import StructResult, tPtr

def get_sdev_state(enum_state):
    if not isinstance(enum_state, long):
        return enum_state
    return {
        1: "SDEV_CREATED",
        2: "SDEV_RUNNING",
        3: "SDEV_CANCEL",
        4: "SDEV_DEL",
        5: "SDEV_QUIESCE",
        6: "SDEV_OFFLINE",
        7: "SDEV_BLOCK",
        8: "SDEV_CREATED_BLOCK",
    }[enum_state]


def print_request_header(request, devid):
    print("{:x} {:<13}".format(int(request), "({})".format(devid)), end='')


def get_queue_requests(rqueue):
    out = []
    for request in readSUListFromHead(rqueue.queue_head, "queuelist",
                                      "struct request"):
        out.append(request)
    return out

def display_requests(fields, usehex):
    for sdev in get_SCSI_devices():
        cmnd_requests = []
        cmnds = get_scsi_commands(sdev)
        for cmnd in cmnds:
            cmnd_requests.append(cmnd.request)

        requests = get_queue_requests(sdev.request_queue)
        requests = list(set(requests + cmnd_requests))
        for req in requests:
            print_request_header(req, get_scsi_device_id(sdev))
            display_fields(req, fields, usehex=usehex)


def get_scsi_hosts():
    shost_class = readSymbol("shost_class")
    klist_devices = 0

    try:
        klist_devices = shost_class.p.class_devices
    except KeyError:
        pass
    if (not klist_devices):
        try:
            klist_devices = shost_class.p.klist_devices
        except KeyError:
            pass

    out = []
    if (klist_devices):
        for knode in klistAll(klist_devices):
            dev = container_of(knode, "struct device", "knode_class")
            out.append(container_of(dev, "struct Scsi_Host", "shost_dev"))
        return out
    else:
        for hostclass in readSUListFromHead(shost_class.children, "node", "struct class_device"):
            out.append(container_of(hostclass, "struct Scsi_Host", "shost_classdev"))
        return out

def get_scsi_commands(sdev):
    out = []
    for cmnd in readSUListFromHead(sdev.cmd_list, "list", "struct scsi_cmnd"):
        out.append(cmnd)
    return out

def get_scsi_device_id(sdev):
    return "{:d}:{:d}:{:d}:{:d}".format(sdev.host.host_no,
                                        sdev.channel, sdev.id, sdev.lun)

def print_cmnd_header(cmnd):
    print("scsi_cmnd {:x} {:<13}".format(int(cmnd),
              "on scsi_device {:#x} ({})".format(cmnd.device, get_scsi_device_id(cmnd.device))), end='')

def print_sdev_header(sdev):
    print("{:x}  {:<12}".format(int(sdev),
              get_scsi_device_id(sdev)), end='')

def print_shost_header(shost):
        print("{:8s}  {:32s}   {:12x} {:24x} {:24x}\n".format(shost.shost_gendev.kobj.name,
            shost.hostt.name, shost, shost.shost_data,
            shost.hostdata, end=""))

def get_gendev():
    gendev_dict = {}
    klist_devices = 0

    if (member_size("struct device", "knode_class") != -1):
        block_class = readSymbol("block_class")

        try:
            klist_devices = block_class.p.class_devices
        except KeyError:
            pass

        if (not klist_devices):
            try:
                klist_devices = block_class.p.klist_devices
            except KeyError:
                pass

        if (klist_devices):
            for knode in klistAll(klist_devices):
                dev = container_of(knode, "struct device", "knode_class")
                hd_temp = container_of(dev, "struct hd_struct", "__dev")
                gendev = container_of(hd_temp, "struct gendisk", "part0")
                gendev_q = format(gendev.queue, 'x')
                gendev_dict[gendev_q] = format(gendev, 'x')

    elif (member_size("struct gendisk", "kobj") != -1):
        block_subsys = readSymbol("block_subsys")
        try:
            kset_list = block_subsys.kset.list
        except KeyError:
            pass

        if (kset_list):
            for kobject in readSUListFromHead(kset_list, "entry", "struct kobject"):
                gendev = container_of(kobject, "struct gendisk", "kobj")
                gendev_q = format(gendev.queue, 'x')
                gendev_dict[gendev_q] = format(gendev, 'x')

    else:
        print("Unable to process the vmcore, cant find 'struct class' or 'struct subsystem'.")
        return

    return gendev_dict

def print_sdev_shost():
    enum_sdev_state = EnumInfo("enum scsi_device_state")

    gendev_dict = get_gendev()

    for shost in get_scsi_hosts():
        if (shost.__devices.next != shost.__devices.next.next):
            print("\n=============================================================================="
                  "===============================================================================")
            print("HOST      DRIVER")
            print("NAME      NAME                               {:24s} {:24s} {:24s}".format("Scsi_Host",
                  "shost_data", "&.hostdata[0]", end=""))
            print("--------------------------------------------------------"
                  "-------------------------------------------------------")

            print_shost_header(shost)

            print("{:17s} {:23s} {:16s} {:25s} {:24s}   {}  {}    {}"
                  "\n".format("DEV NAME", "scsi_device", "H:C:T:L", "VENDOR/MODEL",
                  "DEVICE STATE", "IOREQ-CNT", "IODONE-CNT",
                  "           IOERR-CNT"), end="")
            print("-----------------------------------------------------"
                  "-----------------------------------------------------"
                  "---------------------------------------------------")

            for sdev in readSUListFromHead(shost.__devices, "siblings", "struct scsi_device"):
                name = scsi_device_type(sdev.type)

                if (name):
                    if (name in 'Sequential-Access'):
                        name = "Tape"
                    elif (name in 'Medium Changer   '):
                        name = "Chngr"
                    elif (name in 'RAID             '):
                        name = "CTRL"
                    elif ((name in 'Direct-Access    ') or
                          (name in 'CD-ROM           ')):
                         sdev_q = StructResult("struct request_queue", long(sdev.request_queue))
                         sdev_q = format(sdev_q, 'x')
                         try:
                             gendev = gendev_dict[sdev_q]
                             gendev = readSU("struct gendisk", long (gendev, 16))
                             name = gendev.disk_name
                         except:
                             name = "Disk"
                else:
                    name = "null"

                print("{:17s} {:x} {:6s} {:16} {} {} {:22s}"
                      "{:14d} {:11}  ({:3d})\t{:10d}\n".format(name,
                      int(sdev), "", get_scsi_device_id(sdev),
                      sdev.vendor[:8], sdev.model[:16],
                      get_sdev_state(enum_sdev_state.getnam(sdev.sdev_state)),
                      sdev.iorequest_cnt.counter, sdev.iodone_cnt.counter,
                      sdev.iorequest_cnt.counter-sdev.iodone_cnt.counter,
                      sdev.ioerr_cnt.counter), end='')

def print_starget_shost():
    enum_starget_state = EnumInfo("enum scsi_target_state")
    stgt_busy_block_cnt = -1

    for shost in get_scsi_hosts():
        if (shost.__targets.next != shost.__targets.next.next):
            print("\n======================================================="
                  "========================================================")
            print("HOST      DRIVER")
            print("NAME      NAME                               {:24s} {:24s} {:24s}".format("Scsi_Host",
                  "shost_data", "&.hostdata[0]"))
            print("--------------------------------------------------------"
                  "-------------------------------------------------------")

            print_shost_header(shost)

            print("----------------------------------------------------"
                  "----------------------------------------------------")
            print("{:15s} {:20s} {:8s} {:6s} {:20s} {:15s} {:15s}".format("TARGET DEVICE",
                  "scsi_target", "CHANNEL", "ID", "TARGET STATUS", 
                  "TARGET_BUSY", "TARGET_BLOCKED"))

            for starget in readSUListFromHead(shost.__targets, "siblings", "struct scsi_target"):

                if (member_size("struct scsi_target", "target_busy") != -1):
                    try:
                        stgt_busy_block_cnt = readSU("struct scsi_target", long(starget.target_busy.counter))
                    except:
                        stgt_busy_block_cnt = -1

                    try:
                        sdev_state = get_sdev_state(enum_starget_state.getnam(starget.state))
                        print("{:15s} {:x} {:3s} {:5d} {:5d} {:4s}"
                              "{:20s}".format(starget.dev.kobj.name,
                              int(starget), "", starget.channel,
                              starget.id, "", sdev_state), end='') 

                        if (stgt_busy_block_cnt != -1):
                            print("{:12d} {:18d}".format(starget.target_busy.counter,
                                  starget.target_blocked.counter))

                        elif (stgt_busy_block_cnt == -1 and
                              member_size("struct scsi_target", "target_busy") == -1):
                            print(" <Not defined in scsi_target>")

                        else:
                            print("{:12d} {:18d}".format(starget.target_busy,
                                  starget.target_blocked))

                    except KeyError:
                        pylog.warning("Error in processing scsi_target {:x},"
                                      "please check manually".format(int(starget)))

def print_shost_info():
    use_host_busy_counter = -1

    enum_shost_state = EnumInfo("enum scsi_host_state")

    hosts = get_scsi_hosts()

    try:
        use_host_busy_counter = readSU("struct Scsi_Host", long(hosts[0].host_busy.counter))
    except:
        use_host_busy_counter = -1

    for shost in hosts:
        print("\n============================================================="
              "============================================================")
        print("HOST      DRIVER")
        print("NAME      NAME                               {:24s} {:24s} {:24s}".format("Scsi_Host",
              "shost_data", "&.hostdata[0]", end=""))
        print("-------------------------------------------------------------"
              "------------------------------------------------------------")

        print("{:8s}  {:32s}   {:12x} {:24x} {:24x}".format(shost.shost_gendev.kobj.name,
            shost.hostt.name, shost, shost.shost_data,
            shost.hostdata, end=""))

        try:
            print("\n   DRIVER VERSION      : {}".format(shost.hostt.module.version), end="")
        except:
            print("\n   DRIVER VERSION      : {}".format("Error in checking "
                                                             "'Scsi_Host->hostt->module->version'"), end="")

        if (use_host_busy_counter != -1):
            print("\n   HOST BUSY           : {}".format(shost.host_busy.counter), end="")
            print("\n   HOST BLOCKED        : {}".format(shost.host_blocked.counter), end="")
        else:
            print("\n   HOST BUSY           : {}".format(shost.host_busy), end="")
            print("\n   HOST BLOCKED        : {}".format(shost.host_blocked), end="")

        print("\n   HOST FAILED         : {}".format(shost.host_failed), end="")
        print("\n   SELF BLOCKED        : {}".format(shost.host_self_blocked), end="")
        print("\n   SHOST STATE         : {}".format(enum_shost_state.getnam(shost.shost_state)), end="")
        print("\n   MAX LUN             : {}".format(shost.max_lun), end="")
        print("\n   CMD/LUN             : {}".format(shost.cmd_per_lun), end="")
        print("\n   WORK Q NAME         : {}".format(shost.work_q_name), end="")

def print_request_queue():
    counter = 0
    cmnd_requests = []
    gendev_dict = get_gendev()
    jiffies = readSymbol("jiffies")

    opcode_table = {'0x00':'TUR', '0x03':'REQ-SENSE', '0x08':'READ(6)',\
                    '0x0a':'WRITE(6)', '0x12':'INQUIRY', '0x16':'RESERVE(6)',\
                    '0x17':'RELEASE(6)', '0x25':'READ-CAP(10)', '0x28':'READ(10)',\
                    '0x2a':'WRITE(10)', '0x41':'WR SAME', '0x56':'RESERVE(10)',\
                    '0x57':'RELEASE(10)', '0x88':'READ(16)', '0x8a':'WRITE(16)',\
                    '0xa0':'REPORT LUNS', '0xa8':'READ(12)', '0xaa':'WRITE (12)'}

    for sdev in get_SCSI_devices():
        name = scsi_device_type(sdev.type)
        if (name):
            if ((name in 'Direct-Access    ') or
                (name in 'CD-ROM           ')):
               sdev_q = StructResult("struct request_queue", long(sdev.request_queue))
               if (member_size("struct elevator_queue", "elevator_type") != -1):
                   elevator_name = sdev_q.elevator.elevator_type.elevator_name
               elif(member_size("struct elevator_queue", "type") != -1):
                   elevator_name = sdev_q.elevator.type.elevator_name
               else:
                   elevator_name = "<Unknown>"
               sdev_q = format(sdev_q, 'x')
               try:
                   gendev = gendev_dict[sdev_q]
                   gendev = readSU("struct gendisk", long (gendev, 16))
                   name = gendev.disk_name
               except:
                   name = "Disk"

               print("\n==========================================================="
                     "============================================================")
               print("    ### DEVICE : {}\n".format(name))

               print("        ----------------------------------------------------"
                     "-----------------------------------")
               print("\tgendisk        \t:  {:x}\t|\tscsi_device \t:  {:x}".format(int(gendev), int(sdev)))
               print("\trequest_queue  \t:  {}\t|\tH:C:T:L       \t:  {}".format(sdev_q,
                     sdev.sdev_gendev.kobj.name))
               print("\televator_name  \t:  {}    \t\t|\tVENDOR/MODEL\t:  {} {}".format(elevator_name,
                     sdev.vendor[:8], sdev.model[:16]))
               print("        ----------------------------------------------------"
                     "-----------------------------------")

               cmnd_requests = []
               cmnds = get_scsi_commands(sdev)
               for cmnd in cmnds:
                   cmnd_requests.append(cmnd.request)

               requests = get_queue_requests(sdev.request_queue)
               requests = list(set(requests + cmnd_requests))

               print("\n     {:10s}{:20s} {:20s} {:18s} {:10s} {:20s} {:10s}".format("NO.", "request",
                     "bio", "scsi_cmnd", "OPCODE", "COMMAND AGE", "SECTOR"))
               print("     -------------------------------------------------------"
                     "------------------------------------------------------")

               counter = 0
               for req in requests:
                   counter = counter + 1
                   cmnd = StructResult("struct scsi_cmnd", long(req.special))
                   try:
                       time = (long(jiffies) - long(cmnd.jiffies_at_alloc))
                       opcode = StructResult("struct scsi_cmnd", long(cmnd.cmnd[0]))
                       opcode = hex(opcode)
                       try:
                           opcode = opcode_table[opcode]
                       except:
                           pass
                       print("     {:3d} {:3s} {:18x} {:20x} {:20x}   {:10} {:8d} ms ".format(counter, "",
                             req, req.bio, cmnd, opcode, long(time)), end="")
                       if (req.bio):
                           print("{:15d}".format(req.bio.bi_sector))
                       else:
                           print("       ---NA---")
                   except:
                       pylog.warning("Invalid scsi_cmnd address in request: ", name,  req, cmnd)
               if (counter == 0):
                   print("\t\t<<< NO I/O REQUESTS FOUND ON THE DEVICE! >>>")


def lookup_field(obj, fieldname):
    segments = fieldname.split("[")
    while (len(segments) > 0):
        obj = obj.Eval(segments[0])
        if (len(segments) > 1):
            offset = segments[1].split("]")
            if (isinstance(obj, SmartString)):
                obj = obj[long(offset[0])]
            else:
                obj = obj.__getitem__(long(offset[0]))

            if ((len(offset) > 1) and offset[1]):
                # We've consumed one segment, toss it and replace the next
                # segment with a string witout the "]."
                segments = segments[1:]
                #FIXME: we need to drop a leading ".", but should check first
                segments[0] = offset[1][1:]
            else:
                return obj
        else:
            return obj
    return obj


def display_fields(display, fieldstr, evaldict={}, usehex=0, relative=0):
    evaldict['display'] = display
    for fieldname in fieldstr.split(","):
        field = lookup_field(display, fieldname)
#        field = eval("display.{}".format(fieldname),{}, evaldict)
        if (relative):
            try:
                field = long(field) - long(relative)
            except ValueError:
                field = long(field) - long(readSymbol(relative))

        if (usehex or isinstance(field, StructResult) or
                      isinstance(field, tPtr)):
            try:
                print(" {}: {:<#10x}".format(fieldname, field), end='')
            except ValueError:
                print(" {}: {:<10}".format(fieldname, field), end='')
        else:
            print(" {}: {:<10}".format(fieldname, field), end='')
    del evaldict['display']
    print("")

#x86_64 only!
def is_kernel_address(addr):
    if ((addr & 0xffff000000000000) != 0xffff000000000000):
        return 0
    if (addr > -65536):
        return 0
    if ((addr & 0xfffff00000000000) == 0xffff800000000000):
        return 1
    if ((addr & 0xffffff0000000000) == 0xffffea0000000000):
        return 1
    if ((addr & 0xffffffff00000000) == 0xffffffff00000000):
        return 1
    return 0

def display_command_time(cmnd):
    rq_start_time = 0
    start_time = 0
    deadline = 0
    jiffies = readSymbol("jiffies")
    state = "unknown"

    # get time scsi_cmnd allocated/started
    try:
        start_time = cmnd.jiffies_at_alloc
    except KeyError:
        pass

    if (start_time):
        start_time -= jiffies
    else:
        start_time = "Err"

    try:
        rq_start_time = cmnd.request.start_time
    except KeyError:
        pass

    # get time request allocated/started
    if (rq_start_time):
        rq_start_time -= jiffies
    else:
        rq_start_time = "Err"

    try:
        deadline = cmnd.request.deadline

        if (long(cmnd.request.timeout_list.next)
               != long(cmnd.request.timeout_list)):
            state = "active"
        elif (cmnd.eh_entry.next and
              (long(cmnd.eh_entry.next) != long(cmnd.eh_entry))):
            state = "timeout"
        #csd.list next/prev pointers  may be uninitiallized, so check for sanity
        elif (cmnd.request.csd.list.next and cmnd.request.csd.list.prev and
              (long(cmnd.request.csd.list.next) != long(cmnd.request.csd.list))
              and is_kernel_address(long(cmnd.request.csd.list.next)) and
              is_kernel_address(long(cmnd.request.csd.list.prev))):
            state = "softirq"
        elif (long(cmnd.request.queuelist) != long(cmnd.request.queuelist.next)):
            state = "queued"

    except KeyError:
        pass

    try:
        deadline = cmnd.eh_timeout.expires
        if (cmnd.eh_timeout.entry.next):
            state = "active"
        elif (cmnd.eh_entry.next and
              (long(cmnd.eh_entry.next) != long(cmnd.eh_entry))):
            state = "timeout"
        elif (long(cmnd.request.queuelist) != long(cmnd.request.queuelist.next)):
            state = "queued"
        elif (long(cmnd.request.donelist) != long(cmnd.request.donelist.next)):
            state = "softirq"
    except KeyError:
        pass

    # get time to timeout or state
    if (deadline):
        deadline -= jiffies
    else:
        deadline = "N/A"

    print(" is {}, deadline: {} cmnd-alloc: {} rq-alloc: {}".format(state, deadline, start_time, rq_start_time), end='')


def run_scsi_checks():
    warnings = 0
    errors = 0
    use_host_busy_counter = -1
    gendev_q_sdev_q_mismatch = 0
    jiffies = readSymbol("jiffies")

    # host checks
    hosts = get_scsi_hosts()

    try:
        use_host_busy_counter = readSU("struct Scsi_Host", long(hosts[0].host_busy.counter))
    except:
        use_host_busy_counter = -1

    if (use_host_busy_counter == -1):
        for host in hosts:
            if (host.host_failed):
                warnings += 1
                if (host.host_failed == host.host_busy):
                    print("WARNING: Scsi_Host {:#x} ({}) is running error recovery!".format(host,
                           host.shost_gendev.kobj.name))
                else:
                    print("WARNING: Scsi_Host {:#x} ({}) has timed out commands, but has not started error recovery!".format(host,
                           host.shost_gendev.kobj.name))
            if (host.host_blocked):
                warnings += 1
                print("WARNING: Scsi_Host {:#x} ({}) is blocked! HBA driver refusing all commands with SCSI_MLQUEUE_HOST_BUSY?".format(host,
                       host.shost_gendev.kobj.name))

    elif (use_host_busy_counter != -1):
        for host in hosts:
            if (host.host_failed):
                warnings += 1
                if (host.host_failed == host.host_busy.counter):
                    print("WARNING: Scsi_Host {:#x} ({}) is running error recovery!".format(host,
                           host.shost_gendev.kobj.name))
                else:
                    print("WARNING: Scsi_Host {:#x} ({}) has timed out commands, but has not started error recovery!".format(host,
                           host.shost_gendev.kobj.name))
            if (host.host_blocked.counter):
                warnings += 1
                print("WARNING: Scsi_Host {:#x} ({}) is blocked! HBA driver refusing all commands with SCSI_MLQUEUE_HOST_BUSY?".format(host,
                       host.shost_gendev.kobj.name))

    # device checks
    gendev_dict = get_gendev()

    for sdev in get_SCSI_devices():
        if (use_host_busy_counter == -1):
            if (sdev.device_blocked):
                warnings += 1
                print("WARNING: scsi_device {:#x} ({}) is blocked! HBA driver returning "
                      "SCSI_MLQUEUE_DEVICE_BUSY or device returning SAM_STAT_BUSY?".format(sdev,
                      get_scsi_device_id(sdev)))
        elif (use_host_busy_counter != -1):
            if (sdev.device_blocked.counter):
                warnings += 1
                print("WARNING: scsi_device {:#x} ({}) is blocked! HBA driver returning "
                      "SCSI_MLQUEUE_DEVICE_BUSY or device returning SAM_STAT_BUSY?".format(sdev,
                      get_scsi_device_id(sdev)))

        # Check if scsi_device->request_queue is same as corresponding gendisk->queue.
        name = scsi_device_type(sdev.type)
        if (name):
            if (name in 'Direct-Access    '):
                sdev_q = StructResult("struct request_queue", long(sdev.request_queue))
                sdev_q = format(sdev_q, 'x')
                try:
                    gendev = gendev_dict[sdev_q]
                except:
                    gendev_q_sdev_q_mismatch += 1

        # command checks
        for cmnd in get_scsi_commands(sdev):
            try:
                timeout = cmnd.request.timeout
            except KeyError:
                timeout = 0

            if(not timeout):
                try:
                    timeout = cmnd.timeout_per_command
                except KeyError:
                    print("Error: cannot determine timeout!")

            # Check for large timeout values
            if (timeout > 300000):
                errors += 1
                print("ERROR: scsi_cmnd {:#x} on scsi_device {:#x} ({}) has a huge timeout of {}ms!".format(cmnd,
                       cmnd.device, get_scsi_device_id(cmnd.device), timeout))
            elif (timeout == 300000):
                warnings += 1
                print("WARNING: 5 minute timeout found for scsi_cmnd {:#x}! on scsi_device {:#x} ({}) "
                      "Update device-mapper-multipath?".format(cmnd, cmnd.device, get_scsi_device_id(cmnd.device)))
            elif (timeout > 60000):
                warnings += 1
                print("WARNING: scsi_cmnd {:#x} on scsi_device {:#x} ({}) has a large timeout of {}ms.".format(cmnd,
                       cmnd.device, get_scsi_device_id(cmnd.device), timeout))

            # check for old command
            if (timeout and jiffies > (timeout + cmnd.jiffies_at_alloc)):
                print("Warning: scsi_cmnd {:#x} on scsi_device {:#x} ({}) older than its timeout: "
                      "EH or stalled queue?".format(cmnd, cmnd.device, get_scsi_device_id(cmnd.device)))
                warnings += 1

    # scsi_target checks
    stgt_busy_block_cnt = -1
    for shost in get_scsi_hosts():
        if (shost.__targets.next != shost.__targets.next.next):
            for starget in readSUListFromHead(shost.__targets, "siblings", "struct scsi_target"):
                if (member_size("struct scsi_target", "target_busy") != -1):
                    try:
                        stgt_busy_block_cnt = readSU("struct scsi_target", long(starget.target_busy.counter))
                    except:
                        stgt_busy_block_cnt = -1

                    try:
                        if (stgt_busy_block_cnt != -1):
                            if (starget.target_busy.counter > 0):
                                print("WARNING: scsi_target {:10s} {:x} is having non-zero "
                                      "target_busy count: {:d}".format(starget.dev.kobj.name,
                                      int(starget), starget.target_busy.counter))
                                warnings += 1
                            if (starget.target_blocked.counter > 0):
                                print("WARNING: scsi_target {:10s} {:x} is blocked "
                                      "(target_blocked count: {:d})".format(starget.dev.kobj.name,
                                      int(starget), starget.target_blocked.counter))
                                warnings += 1

                        elif (stgt_busy_block_cnt == -1 and
                              member_size("struct scsi_target", "target_busy") != -1):
                            if (starget.target_busy > 0):
                                print("WARNING: scsi_target {:10s} {:x} is having non-zero "
                                      "target_busy count: {:d}".format(starget.dev.kobj.name,
                                      int(starget), starget.target_busy))
                                warnings += 1
                            if (starget.target_blocked > 0):
                                print("WARNING: scsi_target {:10s} {:x} is blocked "
                                      "(target_blocked count: {:d})".format(starget.dev.kobj.name,
                                      int(starget), starget.target_blocked))
                                warnings += 1

                    except KeyError:
                        pylog.warning("Error in processing scsi_target {:x},"
                                      "please check manually".format(int(starget)))

    if (gendev_q_sdev_q_mismatch != 0):
        print("\n\tNOTE: The scsi_device->request_queue is not same as gendisk->request_queue\n"
                "\t      for {} scsi device(s). \n\n"
                "\t      It is likely that custom multipathing solutions have created 'gendisk',\n"
                "\t      'request_queue' structures which are not registered with kernel.\n"
                "\t      *Although this may or may not be a reason for issue, but it could make\n"
                "\t      the analysis of scsi_device, request_queue and gendisk struct confusing!\n"
                .format(gendev_q_sdev_q_mismatch))

    if (not (warnings or errors or gendev_q_sdev_q_mismatch)):
        print("Nothing found")

if ( __name__ == '__main__'):

    import argparse
    parser =  argparse.ArgumentParser()

    parser.add_argument("-p", "--proc", dest="proc_info", default = 0,
        action="store_true",
        help="show /proc/scsi/scsi style information")

    parser.add_argument("-d", "--devices", dest="devs", nargs='?',
                const="device_busy,sdev_state", default=0, metavar="FIELDS",
        help="show all devices")

    parser.add_argument("-s", "--hosts", dest="hosts", nargs='?',
                const="host_busy,host_failed", default=0, metavar="FIELDS",
        help="show all hosts")

    parser.add_argument("-T", "--Targets", dest="targets", nargs='?',
                const="target_busy", default=0, metavar="FIELDS",
        help="show all the scsi targets")

    parser.add_argument("-c", "--commands", dest="commands", nargs='?',
        const="jiffies_at_alloc", default=0, metavar="FIELDS",
        help="show SCSI commands")

    parser.add_argument("-q", "--queue", dest="queue", nargs='?',
        const="jiffies_at_alloc", default=0, metavar="FIELDS",
        help="show the IO requests, SCSI commands from request_queue")

    parser.add_argument("-r", "--requests", dest="requests", nargs='?',
        const="start_time,special", default=0, metavar="FIELDS",
        help="show requests to SCSI devices (INCOMPLETE)")

    parser.add_argument("-x", "--hex", dest="usehex", default = 0,
        action="store_true",
        help="display fields in hex")

    parser.add_argument("--check", dest="runcheck", default = 0,
        action="store_true",
        help="check for common SCSI issues")

    parser.add_argument("--time", dest="time", default = 0,
        action="store_true",
        help="display time and state information for  SCSI commands")

    parser.add_argument("--relative", dest="relative", nargs='?',
        const="jiffies", default=0,
        help="show fields relative to the given value/symbol.  Uses jiffies without argument")


    args = parser.parse_args()

    if (args.runcheck):
        run_scsi_checks()

    if (args.proc_info):
        print_SCSI_devices()

    if (args.commands or args.time):
        cmndcount = 0
        for sdev in get_SCSI_devices():
            cmndlist = get_scsi_commands(sdev)
            for cmnd in cmndlist:
                print_cmnd_header(cmnd)
                if (args.time):
                    display_command_time(cmnd)

                if (args.commands):
                    display_fields(cmnd, args.commands, 
                               usehex=args.usehex,
                               relative=args.relative)
                else:
                    print("")
            cmndcount += len(cmndlist)
        if (not cmndcount):
            print("No SCSI commands found")

    if (args.devs):
        print_sdev_shost()

    if (args.targets):
        print_starget_shost()

    if (args.requests):
        display_requests(args.requests, args.usehex)

    if (args.queue):
        print_request_queue()

    if(args.hosts or not (args.runcheck or args.proc_info or args.devs or
       args.commands or args.requests or args.time or args.targets or
       args.queue)):
        print_shost_info()
