# -*- coding: utf-8 -*-
# module LinuxDump.kobjects
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
This is a package providing generic access to kobjects/klist/kref stuff
'''

from pykdump.API import *

# Iterate klist_devices
def klistAll(klist):
    try:
        return readSUListFromHead(klist.k_list, "n_node", "struct klist_node")
    except KeyError:
        return readSUListFromHead(klist.list, "n_node", "struct klist_node")

#static inline const char *dev_name(const struct device *dev)
#{
        #/* Use the init name until the kobject becomes available */
        #if (dev->init_name)
                #return dev->init_name;

        #return kobject_name(&dev->kobj);
#}

def dev_name(dev):
    try:
        if (dev.init_name):
            return dev.init_name
    except:
        pass
    return kobj_name(dev.kobj)

#static inline const char *kobject_name(const struct kobject *kobj)
#{
        #return kobj->name;
#}

def kobj_name(kobj):
    return kobj.name
