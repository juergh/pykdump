#!/usr/bin/env/python
from pykdump.API import *

__FILE_MODE_FLAGS='''
#define FMODE_READ     0x1
#define FMODE_WRITE    0x2
'''
FILE_MODE_FLAGS=CDefine(__FILE_MODE_FLAGS)

__MS_FLAGS='''
#define MS_RDONLY        1      /* Mount read-only */
#define MS_NOSUID        2      /* Ignore suid and sgid bits */
#define MS_NODEV         4      /* Disallow access to device special files */
#define MS_NOEXEC        8      /* Disallow program execution */
#define MS_SYNCHRONOUS  16      /* Writes are synced at once */
#define MS_REMOUNT      32      /* Alter flags of a mounted FS */
#define MS_MANDLOCK     64      /* Allow mandatory locks on an FS */
#define MS_DIRSYNC      128     /* Directory modifications are synchronous */
#define MS_NOATIME      1024    /* Do not update access times. */
#define MS_NODIRATIME   2048    /* Do not update directory access times */
#define MS_BIND         4096
#define MS_MOVE         8192
#define MS_REC          16384
#define MS_VERBOSE      32768   /* War is peace. Verbosity is silence.
                                   MS_VERBOSE is deprecated. */
#define MS_SILENT       32768
#define MS_POSIXACL     (1<<16) /* VFS does not apply the umask */
#define MS_UNBINDABLE   (1<<17) /* change to unbindable */
#define MS_PRIVATE      (1<<18) /* change to private */
#define MS_SLAVE        (1<<19) /* change to slave */
#define MS_SHARED       (1<<20) /* change to shared */
#define MS_RELATIME     (1<<21) /* Update atime relative to mtime/ctime. */
#define MS_KERNMOUNT    (1<<22) /* this is a kern_mount call */
#define MS_I_VERSION    (1<<23) /* Update inode I_version field */
#define MS_STRICTATIME  (1<<24) /* Always perform atime updates */
#define MS_SNAP_STABLE  (1<<27) /* Snapshot pages during writeback, if needed */
#define MS_BORN         (1<<29)
#define MS_ACTIVE       (1<<30)
#define MS_NOUSER       (1<<31)
'''
MS_FLAGS=CDefine(__MS_FLAGS)

# FIXME: technically this should be in include/linux/mount.h but we put here
__MNT_FLAGS='''
#define MNT_NOSUID      0x01
#define MNT_NODEV       0x02
#define MNT_NOEXEC      0x04
#define MNT_NOATIME     0x08
#define MNT_NODIRATIME  0x10
#define MNT_RELATIME    0x20
#define MNT_READONLY    0x40    /* does the user want this to be r/o? */
#define MNT_STRICTATIME 0x80

#define MNT_SHRINKABLE  0x100
#define MNT_WRITE_HOLD  0x200

#define MNT_SHARED      0x1000  /* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE  0x2000  /* if the vfsmount is a unbindable mount */
#define MNT_PNODE_MASK  0x3000  /* propagation flag mask */
'''
MNT_FLAGS=CDefine(__MNT_FLAGS)
