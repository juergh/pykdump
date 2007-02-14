#!/usr/bin/env python

import sys, os, os.path
import shutil

from modulefinder import ModuleFinder
from distutils.sysconfig import *

config_h = get_config_h_filename()
srcpython = (config_h[0] == '.')
if (srcpython):
    # We did not run 'make install' and are using the sourcetree
    pylib = os.path.dirname(get_makefile_filename())
    pyvers = os.path.basename(get_config_var('MACHDESTLIB'))
else:
    pylib = get_config_var('LIBP')
    pyvers = os.path.basename(pylib)

class customMF(ModuleFinder):
    def makecopy(self, destdir):
        """Generate a list of files containing the found modules with their
        paths, and copy them to the destination directory.
        """

        # Purge the old directory and recreate it
        if (os.path.isdir(destdir)):
            shutil.rmtree(destdir)
        os.makedirs(destdir)

        # We really want to create everything in destdir/lib/python2.X
        destdir = os.path.join(destdir, "lib", pyvers)
        print
        print "  %-25s %s" % ("Name", "File")
        print "  %-25s %s" % ("----", "----")
        # Print modules found
        keys = self.modules.keys()
        keys.sort()
        preflen = len(pylib)
        for key in keys:
            m = self.modules[key]

            # We are mot interested in anything that is not
            # a real file in PYLIB subdirectories
            if (not m.__file__ or m.__file__.find(pylib) != 0): continue
            
            # If we are copying from srctree (Python built but not installed),
            # we have to strip extra /Lib/ and /build/... directores, e.g.
            # /src/Python/Python-2.4.4/Lib/xml/__init__.py -> xml/__init__.py
            # /src/Python/Python-2.4.4/build/lib.linux-i686-2.4/zlib.so ->
            #                         lib-dynload/zlib.so
            dst = m.__file__[preflen+1:].split('/')

            if (dst[0] == 'Lib'):
                # if dst starts from Lib/, strip it
                dst = dst[1:]
            elif (dst[0] == 'build'):
                dst = ['lib-dynload'] + dst[2:]
            dst = string.join(dst, '/')
            #print "%s -> %s" % (m.__file__, dst)
            destpath = os.path.join(destdir, dst)

            if m.__path__:
                print "P",
            else:
                print "m",
            print "%-25s" % key, m.__file__
            # Now copy this file preserving directory structure and timestamps
            #
            subdir = os.path.dirname(destpath)
            if (not os.path.isdir(subdir)):
                print "\t ++ Creating", subdir
                os.makedirs(subdir)
            shutil.copy2(m.__file__, destpath)

if (len(sys.argv) < 2):
    print pylib, pyvers
    sys.exit(0)
else:
    mod = sys.argv[1]

if (len(sys.argv) > 2):
    outdir = sys.argv[2]
else:
    outdir = "Python32"

sys.path.insert(0, os.path.dirname(mod))
excludes = ['Linuxlib', 'email', 'encodings',
            'xml.parsers', 'xml.sax.expatreader']
mf = customMF(excludes = excludes)
mf.run_script(mod)
#mf.makecopy(outdir)
mf.report()

