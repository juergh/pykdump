 #!/usr/bin/env/python
__author__ = "Dave Wysochanski"
__version__ = "0.1"

from pykdump.API import *
import socket
import struct

from LinuxDump.fs import *
from LinuxDump.fs.nfs4_fs_h import *

def supported_fstype(s_type):
    if s_type != sym2addr("nfs_fs_type") and\
       s_type != sym2addr("nfs4_fs_type"):
          print("Skipping unsupported super_block type %s" % s_type.name)
          return False
    return True

def nfs_client_show_state(o, v):
    # RHEL7 has a 'struct vfsmount' embedded in a 'struct mount'
    if member_size("struct vfsmount", "mnt_devname") > 0:
        mnt = vfsmount = readSU("struct vfsmount", v)
        sb = readSU("struct super_block", mnt.mnt_sb)
    else:
        mnt = readSU("struct mount", v)
        sb = readSU("struct super_block", mnt.mnt.mnt_sb)
        vfsmount = readSU("struct vfsmount", mnt.mnt)

    if not supported_fstype(sb.s_type):
        return

    s = readSU("struct nfs_server", sb.s_fs_info)

    if mnt.mnt_devname:
        print("mnt_devname = %s" % mnt.mnt_devname)
    else:
        print("mnt_devname = unknown")

    client = nfs_client(s.nfs_client)
    client.print_verbose()

    server = nfs_server(sb.s_fs_info)
    server.print_verbose(o.owner, o.lock, o.delegation)

def nfs_server_show_state(o, v):
    print("Not supported")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('mount', help='- specify  mount/vfsmount addr '
                        ' or mountpoint name. If there are no positional'
                        ' arguments, print info for all NFS mounts', nargs='*')

    parser.add_argument("-a","--all", dest="all", default = 0,
                  action="store_true",
                  help="print all")

    parser.add_argument("--client", dest="client", default = 0,
                  action="store_true",
                  help="print info about this host as an NFS4-client")

    parser.add_argument("--server", dest="server", default = 0,
                  action="store_true",
                  help="print info about this host as an NFS4-server")

    parser.add_argument("-o","--owner", dest="owner", default = 0,
                  action="store_true",
                  help="print NFS4 open_owner information ")

    parser.add_argument("-l","--lock", dest="lock", default = 0,
                  action="store_true",
                  help="print NFS4 lock_owner information")

    parser.add_argument("-d","--delegation", dest="delegation", default = 0,
                  action="store_true",
                  help="print NFS4 delegation information")

    o = parser.parse_args()

    if (o.all):
        o.client = o.server = o.owner = o.lock = o.delegation = True

    mnts = o.mount

    vfs_list = []
    mnt2vfs = {}
    for v, s, t, d, m in getMount():
        if (t in ("nfs", "nfs4")):
            vfs_list.append(v)
            mnt2vfs[m] = v

    if (not mnts):
        mnts = vfs_list

    for sv in mnts:
        # If sv is an integer, this is vfs
        # If arg starts from '/', intepret it as a mountpoint (string)
        # Otherwise, try converting it to hex
        if (isinstance(sv, int)):
            v = sv
        elif (sv.startswith("/")):
            # Strip final '/' if any
            if (sv.endswith('/')):
                sv = sv[:-1]
            # Search for it in mountpoints
            if (sv in mnt2vfs):
                v = mnt2vfs[sv]
            else:
                print("  Nothing is mounted at {}".format(sv))
                continue
        else:
            v = int(sv, 16)

        if o.client:
            nfs_client_show_state(o, v)

        if o.server:
            nfs_server_show_state(o, v)

