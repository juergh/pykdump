# module LinuxDump.scsi.lpfc
#
# --------------------------------------------------------------------
# (C) Copyright 2015-2017 Hewlett Packard Enterprise Development LP
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
This is a submodule of scsi specific for 'lpfc' driver
'''
from pykdump.API import *

def print_extra(shost):
    #struct lpfc_vport *vport = (struct lpfc_vport *) shost->hostdata
    vport = readSU("struct lpfc_vport", shost.hostdata)
    hba = vport.phba
    print("    {}  {}".format(vport, hba))
    link_state = __hba_state_enum.getnam(hba.link_state)
    model = hba.ModelDesc
    if (len(model) == 0):
        pylog.warning("It seems that you are using an incorrect"
            " lpfc debuginfo")
        return
    try:
        model[:3]
    except UnicodeDecodeError:
        return
    print("      Model: {}".format(model))
    print("      Link state: {!r}".format(hba.link_state))

def dummy_print_extra(shost):
    return

rc = loadModule("lpfc")
if (not rc):
    pylog.info("If you want extra details, put 'lpfc' debuginfo file into" 
        " current directory")
    print_extra = dummy_print_extra
else:
    # Initialize some structure deinitions
    __hba_state_enum = EnumInfo("enum hba_state")
