#
# Makefile to build standalone extension (with all Python stuff linked in)
# We rely on the top-level Makefile to build the extension itself,
# here we build Python libraries, zip them and append to the end of executable

PYTHON := python

INSTALL := /usr/bin/install

STDLIBP :=  $(shell $(PYTHON)  ../pyconf.py --stdlib)
COMPALL :=  $(shell $(PYTHON)  ../pyconf.py --compileall)

# This is a directory where extension file will be copied
DESTDIR := /usr/local/lib
DIRMODE= 755

EXT_C = pykdump_c.so
EXT_CPY = mpykdump.so

.PHONY: $(EXT_C) clean find pycompile

all: $(EXT_CPY)

# A minimal Python library
PYLIB = pylib.zip

# Full library: std Python + Pykdump + LinuxDump + Progs
PYFULL = pyfull.zip

# Which files to include by default

FIND = find $(1) -name \*.pyc -o -type d -not \( -name .svn\* -prune \)

$(PYLIB): minpylib.lst pyparsing.pyo
	cat $< | (cd $(STDLIBP); zip $(PWD)/$(PYLIB) -@)
	zip -r $@ pyparsing.pyo

PYFULLPATH = $(PWD)/$(PYFULL)

$(PYFULL): $(PYLIB)
	cp $(PYLIB) $(PYFULL)
	cd ../..; $(call FIND, pykdump)  |  zip  $(PYFULLPATH) -@
	cd ../..; $(call FIND, LinuxDump)  |  zip $(PYFULLPATH) -@
	cd ../..; zip  $(PYFULLPATH) progs/xportshow.py progs/crashinfo.py progs/itest.py

$(EXT_C):
	make -f ../Makefile STATICBUILD=1 EXT=$(EXT_C)


$(EXT_CPY): $(EXT_C) $(PYFULL)
	cat  $(EXT_C) $(PYFULL) >$(EXT_CPY)
	zip -A $(EXT_CPY)

clean:
	make -f ../Makefile clean
	rm -f $(EXT_CPY) $(EXT_C) $(PYLIB) $(PYFULL) pykdump LinuxDump progs

find:
	cd ../..; $(call FIND, LinuxDump)
	cd ../..; $(call FIND, pykdump)

pycompile:
	$(PYTHON) $(COMPALL) ../../pykdump
	$(PYTHON) $(COMPALL) ../../LinuxDump