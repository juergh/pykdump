# -*- coding: utf-8 -*-
# module pykdump.Misc
#
# --------------------------------------------------------------------
# (C) Copyright 2006-2018 Hewlett Packard Enterprise Development LP
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

import textwrap
import operator
import array, copy



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



# markers to draw lines/boxes
_LU = '┌' # '+'
_LL = '└' # '+'
_RU = '┐' #'+'
_RL = '┘' # '+'
_VB = '│' # '|'
_HB = '─' # '-'
#
_LOW_A = '┬'
_RIGHT_A = '├'
_LEFT_A = '┤'

# A line of ASCII/Unicode symbols

class LineU(object):
    def __init__(self, initline = ''):
        self._line = array.array('u', initline)
    def clear(self):
        self._line = array.array('u')
    def putstr(self, s, pos):
        lens = len(s)
        # Do we need to extend?
        extra = pos+lens - self.width()
        if (extra > 0):
            self._line.extend(' ' * extra)
        sa = array.array('u', s)
        self._line[pos:pos+lens] = sa
    def __getitem__(self, x):
        try:
            return self._line[x]
        except IndexError:
            return ' '
    def width(self):
        return len(self._line)
    def __str__(self):
        return self._line.tounicode()


# Extensible 2-dim array of chars (Unicode)

class Array2u(object):
    def __init__(self):
        self._lines = []
        # Absolute positions of top left corner if this object has been placed
        self.x = 0
        self.y = 0
    # Set height. At this moment it is intended to be used for extending only
    def setHeight(self, height):
        curh = len(self._lines)
        for i in range(height - curh):
            self._lines.append(LineU())
    def __get_height(self):
        return len(self._lines)
    def __get_width(self):
        return max([l.width() for l in self._lines])
    # Put string at a given position inside our own widget
    def putstr(self, s, x, y):
        if (y > self.h-1):
            self.setHeight(y+1)
        self._lines[y].putstr(s, x)
    # Put another Array2u object at a given position
    def putobj(self, o, x, y):
        for row, lu in enumerate(o._lines):
            self.putstr(str(lu), x, y+row)
        o.x =  x
        o.y =  y
    def getc(self, x, y):
        return self._lines[y][x]
    def __str__(self):
        out = [str(l).rstrip() for l in self._lines]
        return "\n".join(out)
    w = property(__get_width)
    h = property(__get_height)

class BoxContainer(Array2u):
    def __init__(self, box):
        super().__init__()
        self.topbox = box
        self.putobj(box, 1, 0)
        self.y = box.h
    # Draw lines connecting a child box to another (parent) box
    # We assume that this box is indented compared to its parent
    def connect(self, bparent, bchild):
        # We draw on the parent of other, using its coordinates
        # Points to be connected
        p_x = bparent.x + 2
        p_y = bparent.y + bparent.h - 1
        c_x = bchild.x
        c_y = bchild.y + bchild.h//2
        #print("Connecting ({},{}) to ({},{})".format(c_x, c_y, p_x, p_y))
        # We should test some assumptions here, for now let us skip this step
        self.putstr(_LOW_A, p_x, p_y)
        self.putstr(_LEFT_A, c_x, c_y)
        # Angular marker
        self.putstr(_LL, p_x, c_y)
        # Draw horizontal line from child
        for x in range(p_x+1, c_x):
            self.putstr(_HB, x, c_y)
        # Draw vertical line testing what lies beneath
        for y in range(p_y+1, c_y):
            c = self.getc(p_x, y)
            if (c == _RIGHT_A):
                continue
            elif (c == _LL):
                c = _RIGHT_A
            else:
                c = _VB
            self.putstr(c, p_x, y)
    def add_leaf(self, box):
        self.putobj(box, 5, self.y)
        self.y += box.h
        self.connect(self.topbox, box)
    def add_branch(self, boxcontainer):
        self.putobj(boxcontainer, 4, self.y)
        # Adjust coordinates
        boxcontainer.topbox.x += 4
        boxcontainer.topbox.y += self.y
        self.y += boxcontainer.h
        #print(repr(boxcontainer.topbox))
        self.connect(self.topbox, boxcontainer.topbox)

class Box(Array2u):
    def __init__(self, w, h):
        super().__init__()
        self.putstr(_LU, 0, 0)
        self.putstr(_RU, w-1, 0)
        self.putstr(_LL, 0, h-1)
        self.putstr(_RL, w-1, h-1)

        for row in (0, h-1):
            self.putstr(_HB*(w-2), 1, row)
        for row in range(1, h-1):
            self.putstr(_VB, 0, row)
            self.putstr(_VB, w-1, row)
    # Create a box with text inside, choose box size automaticaly to fit the text
    # Text can be a string with LF embedded
    @classmethod
    def TextBox(cls, s, header = None):
        #if (s is None):
            #s = "Empty"
        lines = s.splitlines()
        pad = 0
        w = max([len(l) for l in lines])
        h = len(lines)
        if (header):
            hlines = header.splitlines()
            wh = max([len(l) for l in hlines])
            hh = len(hlines)+1
            w = max(w, wh)
            h += hh
        else:
            hh = 0
        right_edge = w+2 + pad*2
        left_t = 1+pad
        box = cls(right_edge, h+2+pad*2)
        if (header):
            # Draw header line
            box.putstr(_RIGHT_A, 0, hh)
            box.putstr(_LEFT_A, right_edge-1, hh)
            box.putstr(_HB*(right_edge-2), 1, hh)
            # Put header text
            box.putstr(header, left_t, hh-1)
        for row, l in enumerate(lines):
            box.putstr(l, left_t, row+1+hh+pad)
        return box
    def __repr__(self):
        return (" A box: w={} h={} x={} y={}".format(self.w, self.h, self.x, self.y))




# Simple trees that can be rendered with ASCII-art

class AA_Node(object):
    def __init__(self, o, parent = None):
        self.parent = parent
        self.node = o
        self.children = set()
        self.tags = {}       # For fast lookup
        if (parent):
            parent.children.add(self)
            parent.tags[o] = self
    def get_tag(self):
        return self.node
    def glue(self, anotherbranch):
        # Try to find a child with the matching tag
        mytag = self.get_tag()
        pnode = anotherbranch.tags.get(mytag)
        if (pnode is None):
            return False
        # No need to update the tag
        anotherbranch.children.remove(pnode)
        anotherbranch.children.add(self)
        # Add parent
        self.parent = anotherbranch
        return True
    # Split all children into leaves and branches. Put all leaves into
    # a separate box
    # A simple string version
    def _strleaves(self, width=60):
        leaves_tags = sorted({c.get_tag() for c in self.children if not c.children})
        if (not leaves_tags):
            return None
        out = []
        nleaves = len(leaves_tags)
        if (nleaves <= 20):
            # 5 pids per line
            lout = []
            for row, t in enumerate(leaves_tags):
                if (row > 0 and row%5 == 0):
                    out.append(",".join(lout))
                    lout = []
                lout.append(str(t))
            out.append(",".join(lout))
        else:
            out.append("{} pids in this group".format(nleaves))
        return "\n".join(out)
        #return textwrap.fill(str(leaves_tags), width=width)
    def __str__(self, level = 0):
        out = [str(self.node)]
        # First, get leaves if any
        leavesstr = self._strleaves(60)
        #leavesstr = None
        if (leavesstr):
            out.append('  -------')
            out.append(textwrap.indent(leavesstr, '  '))
            out.append('  -------')
        branches = sorted({c for c in self.children if c.children},
                          key=operator.attrgetter('node') )
        for c in branches:
            out.append(textwrap.indent(str(c), '  '))
        txt = "\n".join(out)
        return txt
        return textwrap.indent(txt, '  ')
    # ASCII-art version (tree grow horizontally)
    def _hleaves(self):
        leaves = self._strleaves()
        if (leaves):
            return Box.TextBox(self._strleaves())
        else:
            return None
    def HorTree(self):
        nodebox = Box.TextBox(str(self.node))
        c = BoxContainer(nodebox)
        # First, get leaves if any
        leavesbox = self._hleaves()
        if (leavesbox):
            c.add_leaf(leavesbox)
        branches = sorted({c for c in self.children if c.children},
                          key=operator.attrgetter('node'))

        for branch in branches:
            brancho = branch.HorTree()
            c.add_branch(brancho)
        return c

