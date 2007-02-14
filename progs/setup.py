#!/usr/bin/env python

from distutils.core import setup

setup(name='LinuxDump',
      version='0.1',
      description='Linux Dump Analysis Using Pykdump',
      author='Alex Sidorenko',
      author_email='asid@hp.com',
      url='http://sourceforge.net/projects/pykdump/',
      license='GPL',
      #package_dir = {'': '..'},
      packages=['LinuxDump', 'LinuxDump.inet'],
     )
