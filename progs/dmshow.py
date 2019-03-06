# --------------------------------------------------------------------
# (C) Copyright 2006-2014 Hewlett-Packard Development Company, L.P.
# (C) Copyright 2014-2015 Red Hat, Inc.
#
# Author: David Jeffery
#
# Contributor:
# - Milan P. Gandhi
#      Added following options:
#       -ll, --list  list multipath devices similar to 'multipath -ll'
#       --lvs        show lvm volume information similar to 'lvs' command
#       --lvuuid     show lvm volume and volume group's UUID
#       --pvs        show physical volume information similar to 'pvs' command
#      Added a check in '--check' option to verify if 'multipathd' is
#        blocked, along with scsi_wq, fc_wq
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


__version__ = "0.0.2"

from pykdump.API import *

from pykdump.wrapcrash import StructResult, tPtr

required_modules = ('dm_mod', 'dm_multipath', 'dm_log', 'dm_mirror',
                    'dm_queue_length', 'dm_round_robin', 'dm_service_time',
                    'dm_region_hash', 'dm_snapshot', 'dm_thin_pool', 'dm_raid')

def get_dm_devices():
    sn = "struct hash_cell"
    nameb = readSymbol("_name_buckets")
    out = []
    off = member_offset(sn, "name_list")
    for b in nameb:
        for a in readListByHead(b):
            hc = readSU("struct hash_cell", a - off)
            out.append((hc.md, hc.name))

    return out

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

#copied from scsishow.  This needs to go into a common module
def display_fields(display, fieldstr, usehex=0):
    for fieldname in fieldstr.split(","):
        field = lookup_field(display, fieldname)
#        field = display.Eval(fieldname)
        if (usehex or isinstance(field, StructResult) or
                      isinstance(field, tPtr)):
            try:
                print(" {}: {:<#10x}".format(fieldname, field), end='')
            except ValueError:
                print(" {}: {:<10}".format(fieldname, field), end='')
        else:
            print(" {}: {:<10}".format(fieldname, field), end='')
    print("")

def get_size(gendisk):
    try:
        if (member_size("struct gendisk", "capacity") != -1):
            return (gendisk.capacity * 512 / 1048576)
        else:
            tmp_hd_struct = readSU("struct hd_struct", long(gendisk.part0))
            return (tmp_hd_struct.nr_sects * 512 / 1048576)
    except:
        pylog.warning("Error in processing 'struct gendisk'", gendisk)
        pylog.warning("To debug this issue, you could manually examine "
                      "the contents of gendisk struct")
        return

def show_table_mpath_priogroup(prio):
    print(" {} 0 {} 1".format(prio.ps.type.name, prio.nr_pgpaths), end="")

    for path in readSUListFromHead(prio.pgpaths, "list", "struct pgpath"):
        path_info = StructResult("struct path_info", path.path.pscontext)

        print(" {}:{} [{}] {}".format(path.path.dev.bdev.bd_dev >> 20,
            path.path.dev.bdev.bd_dev & 0xfffff,
            path.path.dev.bdev.bd_disk.disk_name, path_info.repeat_count), end="")

def show_mpath_info(prio):
    for path in readSUListFromHead(prio.pgpaths, "list", "struct pgpath"):
        block_device = StructResult("struct block_device", path.path.dev.bdev)
        scsi_device = StructResult("struct scsi_device", block_device.bd_disk.queue.queuedata)

        print("\n  `- {} {} {}:{}    ".format(scsi_device.sdev_gendev.kobj.name,
            block_device.bd_disk.disk_name,
            block_device.bd_dev >> 20,
            block_device.bd_dev & 0xfffff), end="")

        enum_sdev_state = EnumInfo("enum scsi_device_state")

        if ('cciss' in block_device.bd_disk.disk_name):
            print("\t[Not a scsi device, skipping scsi_device struct!]", end ="")
        else:
            print("\t[scsi_device: {:#x} sdev_state: {}]".format(scsi_device,
                enum_sdev_state.getnam(scsi_device.sdev_state)), end="")

def show_multipath_list(dev):
    md, name = dev
    dm_table_map = StructResult("struct dm_table", md.map)
    print("------------------------------------------------------------------------------------------")

    mpath = StructResult("struct multipath", dm_table_map.targets.private)
    prio_groups = readSUListFromHead(mpath.priority_groups, "list", "struct priority_group")

    temp_prio_groups_list = readSU("struct list_head", mpath.priority_groups)
    temp_priority_group = StructResult("struct priority_group", temp_prio_groups_list.next)
    temp_pgpath_list = readSU("struct list_head", temp_priority_group.pgpaths)
    temp_pgpath = StructResult("struct pgpath", temp_pgpath_list.next)

    try:
        temp_scsi_device = StructResult("struct scsi_device", temp_pgpath.path.dev.bdev.bd_disk.queue.queuedata)
    except:
        pylog.warning("Error in processing sub paths for multipath device:", name)
        pylog.warning("Use 'dmshow --table|grep <mpath-device-name>' to manually verify sub paths.")
        return

    hash_cell = StructResult("struct hash_cell", md.interface_ptr)
    scsi_id = hash_cell.uuid
    scsi_id = scsi_id.partition("-")

    if ('cciss' in temp_pgpath.path.dev.bdev.bd_disk.disk_name):
        print("{}  ({})  dm-{:<4d}  HP Smart Array RAID Device (cciss)".format(name, scsi_id[2],
            md.disk.first_minor), end="")
    else:
        print("{}  ({})  dm-{:<4d}  {}  {}".format(name, scsi_id[2], md.disk.first_minor,
            temp_scsi_device.vendor[:8], temp_scsi_device.model[:16]), end="")

    print("\nsize={:.2f}M  ".format(get_size(temp_pgpath.path.dev.bdev.bd_disk)), end="")

    if (member_size("struct multipath", "flags") != -1):
        if ((mpath.flags & (1 << 0)) or (mpath.flags & (1 << 1)) or
            (mpath.flags & (1 << 2))):
            print("(queue_if_no_path enabled)  ".format(), end="")
        else:
            print("(queue_if_no_path disabled)  ".format(), end="")

    else:
        if (mpath.queue_if_no_path):
            print("features='1 queue_if_no_path'  ".format(), end="")
        else:
            print("features='0' (queue_if_no_path disabled)  ".format(), end="")

    if (mpath.hw_handler_name):
        print("hwhandler={} hwhandler params={}  ".format(mpath.hw_handler_name,
            mpath.hw_handler_params), end="")
    else:
        print("hwhandler={}  ".format(mpath.hw_handler_name), end="")

    for prio in prio_groups:
        print("\n+- policy='{}' ".format(prio.ps.type.name), end="")
        show_mpath_info(prio)

    print("")

def show_dmsetup_table_multipath(dev):
    md, name = dev
    dm_table_map = StructResult("struct dm_table", md.map)
    print("{}: {} {} multipath".format(name, dm_table_map.targets.begin,
        dm_table_map.targets.len),end="")
    mpath = StructResult("struct multipath", dm_table_map.targets.private)

    # general parameters
    params = []

    if (member_size("struct multipath", "flags") != -1):
        if ((mpath.flags & (1 << 0)) or (mpath.flags & (1 << 1)) or
            (mpath.flags & (1 << 2))):
            params.append("queue_if_no_path")

    else:
        if (mpath.queue_if_no_path):
            params.append("queue_if_no_path")

    print(" {}".format(len(params)), end="")
    for param in params:
        print(" {}".format(param), end="")

    #hw handler parameters
    params = []
    if (mpath.hw_handler_name):
        params.append(mpath.hw_handler_name)
        if (mpath.hw_handler_params):
            for param in mpath.hw_handler_params.split(" "):
                params.append(param)

    print(" {}".format(len(params)), end="")
    for param in params:
        print(" {}".format(param), end="")

    #number of path groups
    print(" {}".format(mpath.nr_priority_groups), end="")

    prio_groups = readSUListFromHead(mpath.priority_groups, "list", "struct priority_group")

    #next pathgroup to try
    if (mpath.current_pg):
        print(" {}".format(mpath.current_pg.pg_num), end="")
    elif (prio_groups):
        print(" {}".format(prio_groups[0].pg_num), end="")
    else:
        print(" 1", end="")

    for prio in prio_groups:
        show_table_mpath_priogroup(prio)

    print("")

def show_basic_mpath_info(dev):
    md, name = dev
    dm_table_map = StructResult("struct dm_table", md.map)
    mpath = StructResult("struct multipath", dm_table_map.targets.private)

    print("dm-{:<4d} {:<22} {:#x} ".format(md.disk.first_minor, name, mpath), end="")

    use_nr_paths_counter = -1

    try:
        use_nr_paths_counter = readSU("struct multipath", long(mpath.nr_valid_paths.counter))
    except:
        use_nr_paths_counter = -1

    if (use_nr_paths_counter != -1):
        print("{:26d}".format(mpath.nr_valid_paths.counter), end="")
    else:
        print("{:26d}".format(mpath.nr_valid_paths), end="")

    if (member_size("struct multipath", "flags") != -1):
        if ((mpath.flags & (1 << 0)) or (mpath.flags & (1 << 1)) or
            (mpath.flags & (1 << 2))):
            print("\t\t{}".format("Enabled"))
        else:
            print("\t\t{}".format("Disabled"))

    else:
        if (mpath.queue_if_no_path):
            print("\t\t{}".format("Enabled"))
        else:
            print("\t\t{}".format("Disabled"))

def get_vg_lv_names(string):
    temp = ["", ""]
    i = flag = 0

    while i < len(string):
        if (string[i-1].isalnum() and string[i+1].isalnum() and string[i] == '-'):
            flag = 1
            i += 1

        if (flag == 0):
            temp[0] = temp[0] + string[i]
        elif (flag == 1):
            temp[1] = temp[1] + string[i]
        i += 1

    return temp

def get_md_mpath_from_gendisk(pv_gendisk):
    tmp_mapped_device = StructResult("struct mapped_device", pv_gendisk.queue.queuedata)
    for temp_dev in devlist:
        if (tmp_mapped_device == temp_dev[0]):
            return temp_dev

def show_linear_lvm(dev):
    md, name = dev
    dm_table_map = StructResult("struct dm_table", md.map)
    for target_id in range(dm_table_map.num_targets):
        target = dm_table_map.targets.__getitem__(target_id)
        linear_c = StructResult("struct linear_c", target.private)
        gendisk = StructResult("struct gendisk", md.disk)
        pv_gendisk = StructResult("struct gendisk", linear_c.dev.bdev.bd_disk)
        hash_cell = StructResult("struct hash_cell", md.interface_ptr)
        try:
            if ('LVM-' not in hash_cell.uuid):
                return
        except:
            pylog.warning("Invalid UUID for mapped_device:", hex(md), 
                          "| hash_cell.uuid (UUID) is:", hash_cell.uuid)
            return

        vg_lv_names = get_vg_lv_names(name)

        if ((vg_lv_names[0]) and (vg_lv_names[1])):

            lv_capacity = get_size(gendisk)

            if ('dm-' in pv_gendisk.disk_name[:3]):
                pv_md, pv_md_name = get_md_mpath_from_gendisk(pv_gendisk)
                print("dm-{:<10d} {:45s} {:40s} "
                       "{} {:18.2f}     {}\t({})\n".format(md.disk.first_minor,
                       vg_lv_names[1], vg_lv_names[0],
                       md.open_count.counter,
                       lv_capacity,
                       pv_md_name, pv_gendisk.disk_name), end="")
            else:
                print("dm-{:<10d} {:45s} {:40s} "
                      "{} {:18.2f}     {}\n".format(md.disk.first_minor,
                      vg_lv_names[1], vg_lv_names[0],
                      md.open_count.counter,
                      lv_capacity,
                      pv_gendisk.disk_name), end="")

def show_linear_lvm_uuid(dev):
    md, name = dev
    dm_table_map = StructResult("struct dm_table", md.map)
    for target_id in range(dm_table_map.num_targets):
        target = dm_table_map.targets.__getitem__(target_id)
        gendisk = StructResult("struct gendisk", md.disk)
        hash_cell = StructResult("struct hash_cell", md.interface_ptr)
        try:
            if ('LVM-' not in hash_cell.uuid):
                return
        except:
            pylog.warning("Invalid UUID for mapped_device:", hex(md), 
                          "| hash_cell.uuid (UUID) is:", hash_cell.uuid)
            return

        lv_uuid = hash_cell.uuid.partition("-")
        lv_uuid = lv_uuid[2]

        vg_lv_names =  get_vg_lv_names(name)

        if ((vg_lv_names[0]) and (vg_lv_names[1])):

             lv_capacity = get_size(gendisk)

             print("dm-{:<10d} {:45s} {:20s} {:18.2f}      {:10s}  {:10s}\n".format(md.disk.first_minor,
                 vg_lv_names[1], vg_lv_names[0],
                 lv_capacity,
                 lv_uuid[-32:], lv_uuid[:32]), end="")

def show_linear_lvm_pv(dev):
    md, name = dev
    dm_table_map = StructResult("struct dm_table", md.map)
    for target_id in range(dm_table_map.num_targets):
        target = dm_table_map.targets.__getitem__(target_id)
        linear_c = StructResult("struct linear_c", target.private)
        gendisk = StructResult("struct gendisk", md.disk)
        pv_gendisk = StructResult("struct gendisk", linear_c.dev.bdev.bd_disk)
        hash_cell = StructResult("struct hash_cell", md.interface_ptr)
        try:
            if ('LVM-' not in hash_cell.uuid):
                return
        except:
            pylog.warning("Invalid UUID for mapped_device:", hex(md), 
                          "| hash_cell.uuid (UUID) is:", hash_cell.uuid)
            return

        vg_lv_names =  get_vg_lv_names(name)

        if ((vg_lv_names[0]) and (vg_lv_names[1])):

            pv_capacity = get_size(pv_gendisk)

            if ('dm-' in pv_gendisk.disk_name[:3]):
                pv_md, pv_md_name = get_md_mpath_from_gendisk(pv_gendisk)
                print("{} ({})\t{:18} {:30x}\t {:32.2f}\t"
                      "{:20s} {}\n".format(pv_md_name,
                      pv_gendisk.disk_name, "", pv_md,
                      pv_capacity,
                      vg_lv_names[0], vg_lv_names[1]), end="")
            else:
                print("{:45s}  {}\t {:25.2f}\t"
                      "{:20s} {}\n".format(pv_gendisk.disk_name,
                      "[PV not on dm dev, skipping!]",
                      pv_capacity,
                      vg_lv_names[0], vg_lv_names[1]), end="")

def show_dmsetup_table_linear(dev):
    md, name = dev
    dm_table_map = StructResult("struct dm_table", md.map)
    for target_id in range(dm_table_map.num_targets):
        target = dm_table_map.targets.__getitem__(target_id)
        linear_c = StructResult("struct linear_c", target.private)

        print("{}: {} {} linear {}:{} [{}] {}".format(name, target.begin,
            target.len, linear_c.dev.bdev.bd_dev >> 20,
            linear_c.dev.bdev.bd_dev & 0xfffff,
            linear_c.dev.bdev.bd_disk.disk_name, linear_c.start))

def show_dmsetup_table(dev):
    md, name = dev
    if (dm_table_map.num_targets == 0):
        print("{}: ".format(name))
    elif (dm_table_map.targets.type.name == "linear"):
        show_dmsetup_table_linear(dev)
    elif (dm_table_map.targets.type.name == "multipath"):
        show_dmsetup_table_multipath(dev)
    else:
        print("{}: {} not yet supported by this command".format(name,
              dm_table_map.targets.type.name))

def run_check_on_multipath():
    errors = 0
    multipathd_daemon = 0   # To verify if multipathd daemon is running
    multipath_blocked = 0   # To verify if multipathd daemon or command is blocked

    mpath_present = 0       # To verify if multipath device exists with or without
                            # multipathd daemon running
    wq_blocked = 0          # To verify if scsi_wq or fc_wq is blocked
    print("\n\n")
    for l in exec_crash_command_bg('ps -m').splitlines()[1:]:
        spl = re.split("\s+", l[1:].strip())
        try:
            days, time, state, pid_disp, pid, task_disp, task_hex, cpu_disp, cpu = spl[:9]
            comm = '   '.join(spl[9:])
            if ('multipathd' in comm):
                multipathd_daemon = 1
            if ((state == '[UN]') and (('multipath' in comm) or ('scsi_wq' in comm) or ('fc_wq' in comm))):
                if ('multipath' in comm):
                    multipath_blocked = 1
                if (('scsi_wq' in comm) or ('fc_wq' in comm)):
                    wq_blocked = 1
                print("[{} {} {} {} {}    \t{} {} {} {}\t{}".format(days, time, state,
                    pid_disp, pid, task_disp, task_hex, cpu_disp, cpu, comm))
        except:
            pylog.warning("cannot parse:", l)

    for dev in devlist:
        md, name = dev
        dm_table_map = StructResult("struct dm_table", md.map)
        if (dm_table_map.targets.type.name == "multipath"):
            mpath_present = 1
            break

    if (mpath_present == 1 and multipathd_daemon == 0):
        print("\n ** multipath device(s) are present, but multipathd service is"
              "\n    not running. IO failover/failback may not work.")
        errors += 1

    if (multipath_blocked == 1 and wq_blocked == 1):
        print("\n ** multipathd and scsi/fc work_queue processes are stuck in UN state,"
            "\n    this could block IO failover on multipath devices")
        errors += 1
    elif (multipath_blocked == 1):
        print("\n ** multipathd processes stuck in UN state,"
              "\n    this could block IO failover on multipath devices")
        errors += 1

    if (errors == 0):
        print("\n    No issues detected by utility.")


if ( __name__ == '__main__'):

    import argparse
    parser =  argparse.ArgumentParser()

    parser.add_argument("-x", "--hex", dest="usehex", default = 0,
        action="store_true",
        help="display fields in hex")

    parser.add_argument("--check", dest="runcheck", default = 0,
        action="store_true",
        help="check for common DM issues (WIP)")

    parser.add_argument("-m", "--multipath", dest="multipath", nargs='?',
        const="nr_valid_paths,queue_io", default=0, metavar="FIELDS",
        help="show multipath devices and fields")

    parser.add_argument("-ll", "--list", dest="multipathlist", nargs='?',
        const="nr_valid_paths,queue_io", default=0, metavar="FIELDS",
        help="show multipath device listing similar to \"multipath -ll\"")

    parser.add_argument("-d", "--mapdev", dest="mapdev", nargs='?',
        const="flags", default=0, metavar="FIELDS",
        help="show mapped_devices and fields")

    parser.add_argument("--table", dest="table", default=0,
        action="store_true",
        help="show \"dmsetup table\" like output")

    parser.add_argument("--lvs", dest="lvs", default=0,
        action="store_true",
        help="show lvm volume information similar to \"lvs\" command")

    parser.add_argument("--lvuuid", dest="lvuuid", default=0,
        action="store_true",
        help="show lvm volume and volume group's UUID")

    parser.add_argument("--pvs", dest="pvs", default=0,
        action="store_true",
        help="show physical volume information similar to \"pvs\" command")

    args = parser.parse_args()


    # Try to load all modules from the required list.
    nodlkms = []
    for m in required_modules:
        if (m in lsModules() and not loadModule(m)):
            nodlkms.append(m)

    # If the required modules could not be loaded, then flag a warning 
    # message about the same
    if (nodlkms):
        s = ", ".join(nodlkms)
        print("\n+++Cannot find debuginfo for DLKMs: {}".format(s))
        sys.exit(0)

    try:
        exec_crash_command("sym dm_table_get_devices")
        exec_crash_command("set scope dm_table_create")
        setscope = 1
    except:
        setscope = 0

    devlist = get_dm_devices()
    devlist = sorted(devlist, key=lambda dev: dev[0].disk.first_minor)
    if (args.multipath):
        print("{}  {:22s} {:30s} {:24s}  {}\n".format("NUMBER", "NAME", "MULTIPATH",
              "nr_valid_paths", "queue_if_no_path"), end="")
    elif (args.multipathlist):
        pass
    elif (args.lvs):
        print("{}   {:45s} {:31s} {:16s} {}     {}\n".format("LV DM-X DEV",
            "LV NAME", "VG NAME", "OPEN COUNT", "LV SIZE (MB)", "PV NAME"), end="")
    elif (args.lvuuid):
        print("{:14s}{:45s} {:26s} {:17s} {:32s}  {}".format("LV DM-X DEV",
            "LV NAME", "VG NAME", "LV SIZE (MB)", "LV UUID", "VG UUID"))
    elif (args.pvs):
        print("{:45s}  {:40s}\t  {}\t{:20s} {}\n".format("PV NAME",
            "PV's MAPPED_DEVICE", "DEVICE SIZE (MB)", "VG NAME", "LV NAME"), end="")
    elif (args.table):
        pass
    else:
        print("NUMBER  NAME                   MAPPED_DEVICE       FIELDS")

    mpathfound = 0

    for dev in devlist:
        md, name = dev
        dm_table_map = StructResult("struct dm_table", md.map)
        if (args.multipath):
            if (not (dm_table_map.targets.type.name == "multipath")):
                continue
            show_basic_mpath_info(dev)
            mpathfound = 1

        elif (args.multipathlist):
            if (not (dm_table_map.targets.type.name == "multipath")):
                continue
            show_multipath_list(dev)
            mpathfound = 1

        elif (args.lvs):
            if (dm_table_map.targets.type.name == "linear"):
                show_linear_lvm(dev)
            elif ((dm_table_map.targets.type.name != "linear") and 
                  (dm_table_map.targets.type.name != "multipath")):
                  print("{}: {} not yet supported by this command".format(name,
                      dm_table_map.targets.type.name))

        elif (args.lvuuid):
            if (dm_table_map.targets.type.name == "linear"):
                show_linear_lvm_uuid(dev)
            elif ((dm_table_map.targets.type.name != "linear") and 
                  (dm_table_map.targets.type.name != "multipath")):
                  print("{}: {} not yet supported by this command".format(name,
                      dm_table_map.targets.type.name))

        elif (args.pvs):
            if (dm_table_map.targets.type.name == "linear"):
                show_linear_lvm_pv(dev)
            elif ((dm_table_map.targets.type.name != "linear") and 
                  (dm_table_map.targets.type.name != "multipath")):
                  print("{}: {} not yet supported by this command".format(name,
                      dm_table_map.targets.type.name))

        elif (args.table):
            show_dmsetup_table(dev)

        else:
            print("dm-{:<4d} {:<22} {:#x} ".format(md.disk.first_minor, name, md), end="")
            if (args.mapdev):
                display_fields(md, args.mapdev, usehex=args.usehex)
            else:
                display_fields(md, "flags", usehex=1)

    if ((args.multipath or args.multipathlist) and (mpathfound == 0)):
        print("\nNo dm-multipath devices found!")

    if (args.pvs):
        print("\n\n   Note: The 'DEVICE SIZE' column shows size of device used for PV, it is\n" 
                 "         not the actual size of PV itself. Since the size of PV could be\n"
                 "         slightly less, depending upon number of PEs and PE size.")

    if (args.runcheck):
        run_check_on_multipath()

    if (setscope):
        exec_crash_command("set scope schedule")
