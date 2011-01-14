#
# Makefile to build standalone extension. We link with a Python library
# build with -fPIC but not linked to .so. That is, something like
# libpython2.7.a
# After that we create ZIP by appending code written in pure Python


# Programs from prog/ ro include
PROGS := crashinfo.py xportshow.py taskinfo.py #itest.py
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

SRCDIR := $(TOPDIR)/Extension
VPATH := $(SRCDIR)

MIN_PYLIST := $(SRCDIR)/$(MINPYLIB_FILES)

EXT_C := pykdump_c.so
EXT_CPY = mpykdump.so

.PHONY: clean pycompile distclean
.DELETE_ON_ERROR:

all: $(EXT_CPY)

INCLUDES := -I$(CRASHDIR) $(PYINCLUDE)
DEFINES = -D$(TARGET)  -DSTATICBUILD -DCRASHVERS=\"$(CRASHVERS)\"
DEBUG =  -g

PYCOMPILE = pycompile

vpath %.c ..

%o: %c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) $< -o $@

gdbspec.o: gdbspec.c
	$(CC) -c $(CFLAGS) $(GDBINCL) $(EXTRA) $(PYINCLUDE)  $< -o $@

OBJS :=  epython.o functions.o gdbspec.o pythonrun.o

PYTHONRUN_C := $(PYTHONDIR)/Python/pythonrun.c

ifeq ($(strip $(wildcard $(PYTHONRUN_C))),)
  PYTHONRUN_C := $(PYTHONDIR)/../Python/pythonrun.c
endif

pythonrun.o: $(PYTHONRUN_C)
	sed 's/Py_Exit(int sts)/xPy_Exit(int sts)/' $(PYTHONRUN_C) >pythonrun.c
	$(CC) -c $(CFLAGS) $(GDBINCL) $(PYINCLUDE)  pythonrun.c -o $@
	@rm -f pythonrun.c


$(EXT_C): $(OBJS) $(PYTHONDIR)/python
	$(CC) -shared  $(LINKFLAGS) $(OBJS) -o $@  $(LIBS)

# A minimal Python library
PYLIB = pylib.zip
PYLIBPREF = pylib

# Full library: std Python + Pykdump + LinuxDump + Progs
PYFULL = pyfull.zip
PYFULLPATH = $(PWD)/$(PYFULL)

pyparsing.pyo: pyparsing.py
	$(PYTHON) -O -c 'import py_compile;py_compile.compile("$^", "$@")'

$(PYLIB): $(MIN_PYLIST) pyparsing.pyo $(PYTHONDIR)/python
	ln -sf  $(STDLIBP) $(PYLIBPREF)
	rm -f $(PYLIB)
	sed -e "s|^|$(PYLIBPREF)/|"  $(MIN_PYLIST) | zip $(PYLIB) -@
	zip $@ pyparsing.pyo
	rm -f $(PYLIBPREF)

FIND = find $(1) -name \*.pyc -o -type d -not \( -name .svn\* -prune \)

$(PYFULL):  $(PYLIB) $(FULLPROGS) $(PYCOMPILE)
	cp $(PYLIB) $(PYFULL)
	cd $(TOPDIR); $(call FIND, pykdump)  |  zip  $(PYFULLPATH) -@
	cd $(TOPDIR); $(call FIND, LinuxDump)  |  zip $(PYFULLPATH) -@
	cd $(TOPDIR); zip  $(PYFULLPATH) $(ZIPPROGS)
	cd $(TOPDIR)/progs;  zip  $(PYFULLPATH) $(INITPROG)


# Before compiling, remove all .pyc files. This might be needed
# if we ran as crash as root (then .pyc are owned by root)
pycompile:
	find $(TOPDIR)/pykdump -name \*.pyc | xargs rm -f
	find $(TOPDIR)/LinuxDump -name \*.pyc | xargs rm -f
	$(PYTHON) $(COMPALL) -f $(TOPDIR)/pykdump
	$(PYTHON) $(COMPALL) -f $(TOPDIR)/LinuxDump

$(EXT_CPY): $(EXT_C) $(PYFULL)
	cat  $(EXT_C) $(PYFULL) >$(EXT_CPY)
	zip -A $(EXT_CPY)
	chmod +x $(EXT_CPY)



clean:
	rm -f $(OBJS) $(EXT_C) $(EXT_CPY) $(PYLIB) $(PYFULL) pyparsing.pyo

distclean:
	rm -f $(OBJS) $(EXT_C) $(EXT_CPY) $(PYLIB) $(PYFULL) pyparsing.pyo *~
