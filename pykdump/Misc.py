# -*- coding: utf-8 -*-
# module pykdump.Misc
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2015 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------
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
Miscelaneous subroutines such as pretty-printing
'''

class EmbeddedFrames(object):
    class SimpleText(object):
        def __init__(self, strarr):
            # If we have one line only, we assume this is a multiline
            if (not isinstance(strarr, list)):
                strarr = strarr.rstrip().split("\n")
            self.strarr = strarr
            # Find dimensions of strarr
            w = 0
            self.h = len(strarr)
            for s in strarr:
                slen = len(s)
                if (slen > w):
                    w = slen
            self.w = w
        def getWH(self):
            return(self.w, self.h)
        def getStrArr(self):
            return self.strarr
    # =================================
    def __init__(self, title):
        self.title = title
        self.children = []
        self.width = 1
        self.height = 1
    def addText(self, strarr):
        #
        self.children.append(EmbeddedFrames.SimpleText(strarr))
        
    def addFrame(self, f):
        self.children.append(f)

    # This are dimensions of frame with text
    def getWH(self):
        # If there are frames among our children, we
        # need to compute their size
        h = 0

        # Width cannot be less than title
        w = len(self.title)+4
        
        for c in self.children:
            wc, wh = c.getWH()
            h += wh
            if (w < wc):
                w = wc

        # We indent frames at the left by 1 space. Then it has 2 | symbols
        # finally, we pad children on the left by one space
        w += 5
        return (w, h)

    # Convert to text
    def getStrArr(self):
        out = []
        w, h = self.getWH()
        first_line = (' +{:-^%d}+' % (w-3)).format(self.title)
        last_line = ' +' + '-' * (w-3) + "+"
        l_format = " | {:%ds} |" % (w-5)
        out.append(first_line)
        
        for c in self.children:
            for s in c.getStrArr():
                out.append(l_format.format(s))
            out.append(l_format.format(""))
        # Remove the last line
        out = out[:-1]
        out.append(last_line)

        return out
    def __str__(self):
        return "\n".join(self.getStrArr())
