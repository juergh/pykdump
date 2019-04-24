#!/usr/bin/env/python
from __future__ import print_function
from pykdump.API import *
from LinuxDump.trees import *

from LinuxDump.fs.fs_h import FILE_MODE_FLAGS

import textwrap

__NFS4_CLIENT_STATE='''
enum nfs4_client_state {
        NFS4CLNT_MANAGER_RUNNING  = 0,
        NFS4CLNT_CHECK_LEASE,
        NFS4CLNT_LEASE_EXPIRED,
        NFS4CLNT_RECLAIM_REBOOT,
        NFS4CLNT_RECLAIM_NOGRACE,
        NFS4CLNT_DELEGRETURN,
        NFS4CLNT_LAYOUTRECALL,
        NFS4CLNT_SESSION_RESET,
        NFS4CLNT_RECALL_SLOT,
        NFS4CLNT_LEASE_CONFIRM,
        NFS4CLNT_SERVER_SCOPE_MISMATCH,
        NFS4CLNT_PURGE_STATE,
        NFS4CLNT_BIND_CONN_TO_SESSION,
        NFS4CLNT_MOVED,
        NFS4CLNT_LEASE_MOVED,
        NFS4CLNT_DELEGATION_EXPIRED,
        NFS4CLNT_RUN_MANAGER,
        NFS4CLNT_DELEGRETURN_RUNNING
};
'''

NFS4_CLIENT_STATE=CEnum(__NFS4_CLIENT_STATE)

class nfs_client():
    def __init__(self, client):
        self.client = readSU("struct nfs_client", client)

    def state_info(self):
        cl_state = { NFS4_CLIENT_STATE.NFS4CLNT_MANAGER_RUNNING: "NFS4CLNT_MANAGER_RUNNING ",
                     NFS4_CLIENT_STATE.NFS4CLNT_CHECK_LEASE: "NFS4CLNT_CHECK_LEASE ",
                     NFS4_CLIENT_STATE.NFS4CLNT_LEASE_EXPIRED: "NFS4CLNT_LEASE_EXPIRED ",
                     NFS4_CLIENT_STATE.NFS4CLNT_RECLAIM_REBOOT: "NFS4CLNT_RECLAIM_REBOOT ",
                     NFS4_CLIENT_STATE.NFS4CLNT_RECLAIM_NOGRACE: "NFS4CLNT_RECLAIM_NOGRACE ",
                     NFS4_CLIENT_STATE.NFS4CLNT_DELEGRETURN: "NFS4CLNT_DELEGRETURN ",
                     NFS4_CLIENT_STATE.NFS4CLNT_LAYOUTRECALL: "NFS4CLNT_LAYOUTRECALL ",
                     NFS4_CLIENT_STATE.NFS4CLNT_SESSION_RESET: "NFS4CLNT_SESSION_RESET ",
                     NFS4_CLIENT_STATE.NFS4CLNT_RECALL_SLOT: "NFS4CLNT_RECALL_SLOT ",
                     NFS4_CLIENT_STATE.NFS4CLNT_LEASE_CONFIRM: "NFS4CLNT_LEASE_CONFIRM ",
                     NFS4_CLIENT_STATE.NFS4CLNT_SERVER_SCOPE_MISMATCH: "NFS4CLNT_SERVER_SCOPE_MISMATCH ",
                     NFS4_CLIENT_STATE.NFS4CLNT_PURGE_STATE: "NFS4CLNT_PURGE_STATE ",
                     NFS4_CLIENT_STATE.NFS4CLNT_BIND_CONN_TO_SESSION: "NFS4CLNT_BIND_CONN_TO_SESSION ",
                     NFS4_CLIENT_STATE.NFS4CLNT_MOVED: "NFS4CLNT_MOVED ",
                     NFS4_CLIENT_STATE.NFS4CLNT_LEASE_MOVED: "NFS4CLNT_LEASE_MOVED ",
                     NFS4_CLIENT_STATE.NFS4CLNT_DELEGATION_EXPIRED: "NFS4CLNT_DELEGATION_EXPIRED ",
                     NFS4_CLIENT_STATE.NFS4CLNT_RUN_MANAGER: "NFS4CLNT_RUN_MANAGER ",
                     NFS4_CLIENT_STATE.NFS4CLNT_DELEGRETURN_RUNNING: "NFS4CLNT_DELEGRETURN_RUNNING "
        }
        print("NFS4 state information:")
        print("- cl_state=0x%x " % self.client.cl_state, end='')
        for f in cl_state:
            if self.client.cl_state & (1 << f):
                print(cl_state[f], end='')
        print(" ")

    def lease_info(self):
        nfs4_lease_time = self.client.cl_lease_time / 1000
        print("NFS4 lease information:")
        print("- cl_lease_time = %d (%d seconds), " % (self.client.cl_lease_time, nfs4_lease_time), end='')
        jiffies = readSymbol("jiffies")
        nfs4_lease_renewed = (jiffies - self.client.cl_last_renewal)/1000
        print("cl_last_renewal = %d (%d seconds ago), " % (self.client.cl_last_renewal, nfs4_lease_renewed))
        if nfs4_lease_renewed < nfs4_lease_time:
            print("- NFS4 lease is _NOT_ expired")
        else:
            print("- NFS4 lease appears expired!")

    def print_verbose(self):
        print("(struct nfs_client *)0x%x" % Deref(self.client))
        self.state_info()
        self.lease_info()

__NFS_DELEGATION_FLAGS='''
enum {
        NFS_DELEGATION_NEED_RECLAIM = 0,
        NFS_DELEGATION_RETURN,
        NFS_DELEGATION_RETURN_IF_CLOSED,
        NFS_DELEGATION_REFERENCED,
        NFS_DELEGATION_RETURNING,
        NFS_DELEGATION_REVOKED,
        NFS_DELEGATION_TEST_EXPIRED,
        NFS_DELEGATION_INODE_FREEING
};
'''

NFS_DELEGATION_FLAGS=CEnum(__NFS_DELEGATION_FLAGS)

# TODO: move to fs/nfs/delegation.h
class nfs_delegation():
    def __init__(self, delegation):
        self.delegation= readSU("struct nfs_delegation", delegation)

    def print_flags(self):
        flags = { NFS_DELEGATION_FLAGS.NFS_DELEGATION_NEED_RECLAIM: "NFS_DELEGATION_NEED_RECLAIM",
                  NFS_DELEGATION_FLAGS.NFS_DELEGATION_RETURN: "NFS_DELEGATION_RETURN",
                  NFS_DELEGATION_FLAGS.NFS_DELEGATION_RETURN_IF_CLOSED: "NFS_DELEGATION_RETURN_IF_CLOSED",
                  NFS_DELEGATION_FLAGS.NFS_DELEGATION_REFERENCED: "NFS_DELEGATION_REFERENCED",
                  NFS_DELEGATION_FLAGS.NFS_DELEGATION_RETURNING: "NFS_DELEGATION_RETURNING",
                  NFS_DELEGATION_FLAGS.NFS_DELEGATION_REVOKED: "NFS_DELEGATION_REVOKED",
                  NFS_DELEGATION_FLAGS.NFS_DELEGATION_TEST_EXPIRED: "NFS_DELEGATION_TEST_EXPIRED",
                  NFS_DELEGATION_FLAGS.NFS_DELEGATION_INODE_FREEING: "NFS_DELEGATION_INODE_FREEING"
        }
        print("- flags=0x%x " % self.delegation.flags, end='')
        for f in flags:
            if self.delegation.flags & (1 << f):
                print(flags[f], end=' ')
        print(" ");

    def print_type(self):
        type = { FILE_MODE_FLAGS.FMODE_READ: "FMODE_READ",
                 FILE_MODE_FLAGS.FMODE_WRITE: "FMODE_WRITE"
        }
        print("- type=0x%x " % self.delegation.type, end='')
        for t in type:
            if self.delegation.type & t:
                print(type[t], end=' ')
        print(" ");

    def print_verbose(self):
        print("(struct nfs_delegation *)0x%x" % Deref(self.delegation))
        print("- inode = 0x%x" % self.delegation.inode)
        self.print_type()
        self.print_flags()

__SERVER_CAPABILITIES='''
#define NFS_CAP_READDIRPLUS     0
#define NFS_CAP_HARDLINKS       1
#define NFS_CAP_SYMLINKS        2
#define NFS_CAP_ACLS            3
#define NFS_CAP_ATOMIC_OPEN     4
#define NFS_CAP_CHANGE_ATTR     5
#define NFS_CAP_FILEID          6
#define NFS_CAP_MODE            7
#define NFS_CAP_NLINK           8
#define NFS_CAP_OWNER           9
#define NFS_CAP_OWNER_GROUP     10
#define NFS_CAP_ATIME           11
#define NFS_CAP_CTIME           12
#define NFS_CAP_MTIME           13
#define NFS_CAP_POSIX_LOCK      14
#define NFS_CAP_UIDGID_NOMAP    15
#define NFS_CAP_STATEID_NFSV41  16
#define NFS_CAP_ATOMIC_OPEN_V1  17
#define NFS_CAP_SECURITY_LABEL  18
#define NFS_CAP_SEEK            19
#define NFS_CAP_ALLOCATE        20
#define NFS_CAP_DEALLOCATE      21
#define NFS_CAP_LAYOUTSTATS     22
#define NFS_CAP_CLONE           23
#define NFS_CAP_COPY            24
#define NFS_CAP_OFFLOAD_CANCEL  25
#define NFS_CAP_LAYOUTERROR     26
'''
SERVER_CAPABILITIES=CDefine(__SERVER_CAPABILITIES)

class nfs_server():
    def __init__(self, server):
        self.server = readSU("struct nfs_server", server)

    def print_capabilities(self):
        capabilities = { SERVER_CAPABILITIES.NFS_CAP_READDIRPLUS: "NFS_CAP_READDIRPLUS",
                         SERVER_CAPABILITIES.NFS_CAP_HARDLINKS: "NFS_CAP_HARDLINKS",
                         SERVER_CAPABILITIES.NFS_CAP_SYMLINKS: "NFS_CAP_SYMLINKS",
                         SERVER_CAPABILITIES.NFS_CAP_ACLS: "NFS_CAP_ACLS",
                         SERVER_CAPABILITIES.NFS_CAP_ATOMIC_OPEN: "NFS_CAP_ATOMIC_OPEN",
                         SERVER_CAPABILITIES.NFS_CAP_CHANGE_ATTR: "NFS_CAP_CHANGE_ATTR",
                         SERVER_CAPABILITIES.NFS_CAP_FILEID: "NFS_CAP_FILEID",
                         SERVER_CAPABILITIES.NFS_CAP_MODE: "NFS_CAP_MODE",
                         SERVER_CAPABILITIES.NFS_CAP_NLINK: "NFS_CAP_NLINK",
                         SERVER_CAPABILITIES.NFS_CAP_OWNER: "NFS_CAP_OWNER",
                         SERVER_CAPABILITIES.NFS_CAP_OWNER_GROUP: "NFS_CAP_OWNER_GROUP",
                         SERVER_CAPABILITIES.NFS_CAP_ATIME: "NFS_CAP_ATIME",
                         SERVER_CAPABILITIES.NFS_CAP_CTIME: "NFS_CAP_CTIME",
                         SERVER_CAPABILITIES.NFS_CAP_MTIME: "NFS_CAP_MTIME",
                         SERVER_CAPABILITIES.NFS_CAP_POSIX_LOCK: "NFS_CAP_POSIX_LOCK",
                         SERVER_CAPABILITIES.NFS_CAP_UIDGID_NOMAP: "NFS_CAP_UIDGID_NOMAP",
                         SERVER_CAPABILITIES.NFS_CAP_STATEID_NFSV41: "NFS_CAP_STATEID_NFSV41",
                         SERVER_CAPABILITIES.NFS_CAP_ATOMIC_OPEN_V1: "NFS_CAP_ATOMIC_OPEN_V1",
                         SERVER_CAPABILITIES.NFS_CAP_SECURITY_LABEL: "NFS_CAP_SECURITY_LABEL",
                         SERVER_CAPABILITIES.NFS_CAP_SEEK: "NFS_CAP_SEEK",
                         SERVER_CAPABILITIES.NFS_CAP_ALLOCATE: "NFS_CAP_ALLOCATE",
                         SERVER_CAPABILITIES.NFS_CAP_DEALLOCATE: "NFS_CAP_DEALLOCATE",
                         SERVER_CAPABILITIES.NFS_CAP_LAYOUTSTATS: "NFS_CAP_LAYOUTSTATS",
                         SERVER_CAPABILITIES.NFS_CAP_CLONE: "NFS_CAP_CLONE",
                         SERVER_CAPABILITIES.NFS_CAP_COPY: "NFS_CAP_COPY",
                         SERVER_CAPABILITIES.NFS_CAP_OFFLOAD_CANCEL: "NFS_CAP_OFFLOAD_CANCEL",
                         SERVER_CAPABILITIES.NFS_CAP_LAYOUTERROR: "NFS_CAP_LAYOUTERROR"
        }
        # print("- caps (capabilities) = 0x%x " % self.server.caps, end='')
        # for c in capabilities:
        #     if self.server.caps & (1 << c):
        #         print(capabilities[c], end=' ')
        # print(" ");
        out = ["- caps (capabilities) = 0x%x" % self.server.caps]
        for c in capabilities:
            if self.server.caps & (1 << c):
                out.append(capabilities[c])
        cstr = ' '.join(out)
        print(textwrap.fill(cstr, initial_indent='',
               subsequent_indent='       '))

    def print_state_owners(self):
        print("nfs_server.state_owners list:")
        for s in for_all_rbtree(self.server.state_owners, "struct nfs4_state_owner", "so_server_node"):
            so = nfs4_state_owner(s)
            so.print_verbose()

    def print_delegations(self):
        print("nfs_server.delegations list:")
        for d in readSUListFromHead(self.server.delegations, 'super_list', 'struct nfs_delegation'):
            delegation = nfs_delegation(d)
            delegation.print_verbose()

    def print_verbose(self, with_open_owners, with_lock_owners, with_delegations):
        print("(struct nfs_server *)0x%x" % Deref(self.server))
        print("- rsize = %d, rpages = %d" % (self.server.rsize, self.server.rpages))
        print("- wsize = %d, wpages = %d" % (self.server.wsize, self.server.wpages))
        print("- wtmult (server disk block size) = %d, bsize (server block size) = %d" % (self.server.wtmult, self.server.bsize))
        print("- dtsize (readdir size) = %d" % self.server.dtsize)
        print("- acregmin = %d, acregmax = %d, acdirmin = %d, acdirmax = %d" %(self.server.acregmin, self.server.acregmax, self.server.acdirmin, self.server.acdirmax))
        self.print_capabilities()
        if with_open_owners:
            try:
                self.print_state_owners()
            except KeyError:
                print(" state owners analysis not implemented for this kernel")
        if with_delegations:
            try:
                self.print_delegations()
            except KeyError:
                print(" delegations analysis not implemented for this kernel")


__NFS4_STATE_OWNER_FLAGS='''
enum {
        NFS_OWNER_RECLAIM_REBOOT,
        NFS_OWNER_RECLAIM_NOGRACE
};
'''
NFS4_STATE_OWNER_FLAGS=CEnum(__NFS4_STATE_OWNER_FLAGS)

class nfs4_state_owner():
    def __init__(self, so):
        self.so = readSU("struct nfs4_state_owner", so)

    def print_state(self):
        flags = { NFS4_STATE_OWNER_FLAGS.NFS_OWNER_RECLAIM_REBOOT: "NFS_OWNER_RECLAIM_REBOOT",
                  NFS4_STATE_OWNER_FLAGS.NFS_OWNER_RECLAIM_NOGRACE: "NFS_OWNER_RECLAIM_NOGRACE"
        }
        print("- so_flags = 0x%x " % self.so.so_flags, end='')
        for f in flags:
            if self.so.so_flags & (1 << f):
                print(flags[f], end=' ')
        print(" ");
    
    def print_nfs4_states(self):
        print("nfs4_state_owner.so_states list:")
        for s in readSUListFromHead(self.so.so_states, 'open_states', 'struct nfs4_state'):
            state = nfs4_state(s)
            state.print_verbose()

    def print_verbose(self):
        print("(struct nfs4_state_owner *)0x%x" % Deref(self.so))
        self.print_state()
        self.print_nfs4_states()

__NFS4_STATE_FLAGS='''
enum {
        LK_STATE_IN_USE,
        NFS_DELEGATED_STATE,                /* Current stateid is delegation */
        NFS_OPEN_STATE,                        /* OPEN stateid is set */
        NFS_O_RDONLY_STATE,                /* OPEN stateid has read-only state */
        NFS_O_WRONLY_STATE,                /* OPEN stateid has write-only state */
        NFS_O_RDWR_STATE,                /* OPEN stateid has read/write state */
        NFS_STATE_RECLAIM_REBOOT,        /* OPEN stateid server rebooted */
        NFS_STATE_RECLAIM_NOGRACE,        /* OPEN stateid needs to recover state */
        NFS_STATE_POSIX_LOCKS,                /* Posix locks are supported */
        NFS_STATE_RECOVERY_FAILED,       /* OPEN stateid state recovery failed */
        NFS_STATE_MAY_NOTIFY_LOCK,      /* server may CB_NOTIFY_LOCK */
        NFS_STATE_CHANGE_WAIT,          /* A state changing operation is outstanding */
        NFS_CLNT_DST_SSC_COPY_STATE    /* dst server open state on client*/
};
'''

NFS4_STATE_FLAGS=CEnum(__NFS4_STATE_FLAGS)
class nfs4_state():
    def __init__(self, state):
        self.state = readSU("struct nfs4_state", state)

    def print_flags(self):
        flags = { NFS4_STATE_FLAGS.LK_STATE_IN_USE: "LK_STATE_IN_USE",
                  NFS4_STATE_FLAGS.NFS_DELEGATED_STATE: "NFS_DELEGATED_STATE",
                  NFS4_STATE_FLAGS.NFS_OPEN_STATE: "NFS_OPEN_STATE",
                  NFS4_STATE_FLAGS.NFS_O_RDONLY_STATE: "NFS_O_RDONLY_STATE",
                  NFS4_STATE_FLAGS.NFS_O_WRONLY_STATE: "NFS_O_WRONLY_STATE",
                  NFS4_STATE_FLAGS.NFS_O_RDWR_STATE: "NFS_O_RDWR_STATE",
                  NFS4_STATE_FLAGS.NFS_STATE_RECLAIM_REBOOT: "NFS_STATE_RECLAIM_REBOOT",
                  NFS4_STATE_FLAGS.NFS_STATE_RECLAIM_NOGRACE: "NFS_STATE_RECLAIM_NOGRACE",
                  NFS4_STATE_FLAGS.NFS_STATE_POSIX_LOCKS: "NFS_STATE_POSIX_LOCKS",
                  NFS4_STATE_FLAGS.NFS_STATE_RECOVERY_FAILED: "NFS_STATE_RECOVERY_FAILED",
                  NFS4_STATE_FLAGS.NFS_STATE_MAY_NOTIFY_LOCK: "NFS_STATE_MAY_NOTIFY_LOCK",
                  NFS4_STATE_FLAGS.NFS_STATE_CHANGE_WAIT: "NFS_STATE_CHANGE_WAIT",
                  NFS4_STATE_FLAGS.NFS_CLNT_DST_SSC_COPY_STATE: "NFS_CLNT_DST_SSC_COPY_STATE"
        }
        print("- flags=0x%x " % self.state.flags, end='')
        for f in flags:
            if self.state.flags & (1 << f):
                print(flags[f], end=' ')
        print(" ");

    def print_openmodes(self):
        print("- n_rdonly: %u n_wronly: %u n_rdwr: %u" %
              (self.state.n_rdonly, self.state.n_wronly, self.state.n_rdwr))

    def print_verbose(self):
        print("(struct nfs4_state *)0x%x" % Deref(self.state))
        self.print_flags()
        self.print_openmodes()


# thanks stackoverflow
def auto_int(x):
    return int(x,0)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('address', type=auto_int)

    parser.add_argument("-o","--nfs4_state_owner", dest="Owner", default = 0,
                  action="store_true",
                  help="address is a (struct nfs4_state_owner )")

    parser.add_argument("-t","--nfs4_state", dest="State", default = 0,
                  action="store_true",
                  help="address is a (struct nfs4_state *)")

    parser.add_argument("-d","--delegation", dest="Delegation", default = 0,
                  action="store_true",
                  help="address is a (struct nfs_delegation *)")

    parser.add_argument("-c","--nfs_client", dest="Client", default = 0,
                  action="store_true",
                  help="address is a (struct nfs_client *)")

    parser.add_argument("-s","--nfs_server", dest="Server", default = 0,
                  action="store_true",
                  help="address is a (struct nfs_server *)")

    args = parser.parse_args()
    if (args.Owner):
        x = nfs4_state_owner(args.address)
        x.print_verbose()
    if (args.State):
        x = nfs4_state(args.address)
        x.print_verbose()
    if (args.Delegation):
        x = nfs_delegation(args.address)
        x.print_verbose()
    if (args.Client):
        x = nfs_client(args.address)
        x.print_verbose()
    if (args.Server):
        x = nfs_server(args.address)
        x.print_verbose(1, 1, 1)

