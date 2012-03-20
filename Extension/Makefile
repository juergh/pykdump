#
# Makefile to build standalone extension. We link with a Python library
# build with -fPIC but not linked to .so. That is, something like
# libpython2.7.a
# After that we create ZIP by appending code written in pure Python


# Programs from prog/ ro include
PROGS := crashinfo.py xportshow.py taskinfo.py nfsshow.py
ZIPPROGS := $(addprefix progs/, $(PROGS))
FULLPROGS =  $(addprefix ../progs/, $(PROGS))
INITPROG := PyKdumpInit.py


# Check whether we ran configure

c_ok := $(wildcard crash.mk)

ifeq ($(strip $(c_ok)),)
not_configured:
	@echo "You need to configure the directories before running make"
	@exit 1
else
  include crash.mk slocal.mk
endif

MK = crash.mk slocal.mk

SRCDIR := $(TOPDIR)/Extension
VPATH := $(SRCDIR)

MIN_PYLIST := $(SRCDIR)/$(MINPYLIB_FILES)

# This is a pure C extension. It can be used with Python2 as it is for testing.
# This is not so with Python3 - it needs some subroutines from its STDLIB
# for proper codecs initialization
EXT_C := pykdump_c.so

# This is C-module with Python STDLIB pieces attached. Suitable for testing
# using 'import crash' (no pykdump/ yet).
EXT_C_PY = crashmin.so

# Now, the same but with our main API included - the contentes of pykdump/
# directory
EXT_FULLAPI = API.so

# Finally, the complete file suitable for production and distribution
EXT_FULL = mpykdump.so

.PHONY: clean distclean README
.DELETE_ON_ERROR:

all: $(EXT_FULL)

INCLUDES := -I$(CRASHDIR) $(PYINCLUDE)
DEFINES = -D$(TARGET)  -DSTATICBUILD -DCRASHVERS=\"$(CRASHVERS)\" \
	-DPYSTDLIBDIR=\"$(PYSTDLIBDIR)\"
DEBUG =  -g

PYCOMPILE = pycompile

vpath %.c ..

%o: %c pykdump.h  $(PYTHONDIR)/python $(MK)
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) $< -o $@

gdbspec.o: gdbspec.c $(PYTHONDIR)/python $(MK)
	$(CC) -c $(CFLAGS) $(GDBINCL) $(EXTRA) $(PYINCLUDE)  $< -o $@

OBJS :=  epython.o functions.o gdbspec.o pythonrun.o

PYTHONRUN_C := $(PYTHONDIR)/Python/pythonrun.c

ifeq ($(strip $(wildcard $(PYTHONRUN_C))),)
  PYTHONRUN_C := $(PYTHONDIR)/../Python/pythonrun.c
endif

pythonrun.o: $(PYTHONRUN_C) $(MK)
	sed 's/Py_Exit(int sts)/xPy_Exit(int sts)/' $(PYTHONRUN_C) >pythonrun.c
	$(CC) -c $(CFLAGS) $(GDBINCL) $(PYINCLUDE)  pythonrun.c -o $@
	@rm -f pythonrun.c


$(EXT_C): $(OBJS) $(PYTHONDIR)/python
	$(CC) -shared  $(LINKFLAGS) $(OBJS) -o $@  $(LIBS)

# A minimal Python library
PYLIB = pylib.zip
# We put parts of Python Standard Library into this directory. It needs to
# be added to sys.path in epython
PYSTDLIBDIR = pylib

# Full library: std Python + Pykdump + LinuxDump + Progs
PYFULL = pyfull.zip
PYFULLPATH = $(PWD)/$(PYFULL)

PYPA = pyparsing_py$(PYMAJOR)
pyparsing.pyo: $(PYPA).py $(MK)
	$(PYTHON) -O -c 'import py_compile;py_compile.compile("$(PYPA).py", "./$@")'


$(PYLIB): $(MIN_PYLIST) pyparsing.pyo $(PYTHONDIR)/python $(MK)
	$(PYTHON) -O makestdlib.py $(STDLIBP) $(PYSTDLIBDIR)  $(MIN_PYLIST)
	zip -r $(PYLIB) $(PYSTDLIBDIR)
	zip $@ pyparsing.pyo
	rm -rf $(PYSTDLIBDIR)

FIND = find $(1) -name \*.pyc -o -type d -not \( -name .svn\* -prune \)

$(PYFULL):  $(PYLIB) $(FULLPROGS) $(PYCOMPILE)
	cp $(PYLIB) $(PYFULL)
	cd $(TOPDIR); $(call FIND, pykdump)  |  zip  $(PYFULLPATH) -@
	cd $(TOPDIR); $(call FIND, LinuxDump)  |  zip $(PYFULLPATH) -@
	cd $(TOPDIR); zip  $(PYFULLPATH) $(ZIPPROGS)
	cd $(TOPDIR)/progs;  zip  $(PYFULLPATH) $(INITPROG)



# For testing of crash module only - our API + Python stdlib
$(EXT_C_PY):  $(EXT_C) $(PYLIB)
	cat  $(EXT_C) $(PYLIB) >$(EXT_C_PY)
	zip -A $(EXT_C_PY)
	chmod +x $(EXT_C_PY)

$(EXT_FULLAPI):  $(EXT_C_PY)
	find $(TOPDIR)/pykdump -name \*.pyc | xargs rm -f
	$(PYTHON) $(COMPALL) -f $(TOPDIR)/pykdump
	cp $(EXT_C_PY) $(EXT_FULLAPI)
	cd $(TOPDIR); $(call FIND, pykdump)  |  zip  $(PWD)/$(EXT_FULLAPI) -@

$(EXT_FULL): $(EXT_FULLAPI) README
	find $(TOPDIR)/LinuxDump -name \*.pyc | xargs rm -f
	$(PYTHON) $(COMPALL) -f $(TOPDIR)/LinuxDump
	cp $(EXT_FULLAPI) $(EXT_FULL)
	zip $(EXT_FULL) README
	cd $(TOPDIR); $(call FIND, LinuxDump)  |  zip  $(PWD)/$(EXT_FULL) -@



# Create a file with basic info about this build, to be added to mpykdump.so
# for identification purposes

README:
	$(PYTHON) writeREADME.py  "$(CRASHVERS) $(TARGET)" "$(EXT_C)" >README

clean:
	rm -f $(OBJS) $(EXT_C) $(EXT_C_PY) $(EXT_FULLAPI) \
		$(PYLIB) $(PYFULL) pyparsing.pyo $(PYLIB)

distclean: clean
	rm -f  pyparsing.pyo *~ *.mk
