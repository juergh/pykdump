#
# Makefile to build standalone extension. We link with nonshared Python library
# and create a ZIP with allpure Python code


# Programs from prog/ ro include
PROGS := crashinfo.py xportshow.py task.py #itest.py
ZIPPROGS := $(addprefix progs/, $(PROGS))
FULLPROGS =  $(addprefix ../../progs/, $(PROGS))
INITPROG := PyKdumpInit.py

# Check whether we ran configure

c_ok := $(wildcard ../crash.mk)

ifeq ($(strip $(c_ok)),)
not_configured:
	@echo "You need to configure the directories before running make"
	@exit 1
else
  include ../crash.mk ../slocal.mk
endif


EXT_C := pykdump_c.so
EXT_CPY = mpykdump.so

.PHONY: clean pycompile distclean
.DELETE_ON_ERROR:

all: $(EXT_CPY)

INCLUDES := -I$(CRASHDIR) $(PYINCLUDE)
DEFINES = -D$(TARGET)  -DSTATICBUILD
DEBUG =  -g

PYCOMPILE = pycompile

vpath %.c ..

%o: %c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) $< -o $@

gdbspec.o: gdbspec.c
	$(CC) -c $(CFLAGS) $(GDBINCL) $(PYINCLUDE)  $< -o $@

OBJS :=  epython.o functions.o gdbspec.o pythonrun.o

PYTHONRUN_C = $(PYTHONDIR)/Python/pythonrun.c

pythonrun.o: $(PYTHONDIR)/Python/pythonrun.c
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
PWD = $(shell pwd)
PYFULLPATH = $(PWD)/$(PYFULL)

pyparsing.pyo: pyparsing.py
	$(PYTHON) -O -c "import pyparsing"

$(PYLIB): $(MINPYLIB_FILES) pyparsing.pyo $(PYTHONDIR)/python
	ln -sf  $(STDLIBP) $(PYLIBPREF)
	rm -f $(PYLIB)
	sed -e "s|^|$(PYLIBPREF)/|"  $(MINPYLIB_FILES) | zip $(PYLIB) -@
	zip $@ pyparsing.pyo
	rm -f $(PYLIBPREF)

FIND = find $(1) -name \*.pyc -o -type d -not \( -name .svn\* -prune \)

$(PYFULL):  $(PYLIB) $(FULLPROGS) $(PYCOMPILE)
	cp $(PYLIB) $(PYFULL)
	cd ../..; $(call FIND, pykdump)  |  zip  $(PYFULLPATH) -@
	cd ../..; $(call FIND, LinuxDump)  |  zip $(PYFULLPATH) -@
	cd ../..; zip  $(PYFULLPATH) $(ZIPPROGS)
	cd ../../progs;  zip  $(PYFULLPATH) $(INITPROG)


# Before compiling, remove all .pyc files. This might be needed
# if we ran as crash as root (then .pyc are owned by root)
pycompile:
	find ../../pykdump -name \*.pyc | xargs rm -f
	find ../../LinuxDump -name \*.pyc | xargs rm -f
	$(PYTHON) $(COMPALL) -f ../../pykdump
	$(PYTHON) $(COMPALL) -f ../../LinuxDump

$(EXT_CPY): $(EXT_C) $(PYFULL)
	cat  $(EXT_C) $(PYFULL) >$(EXT_CPY)
	zip -A $(EXT_CPY)
	chmod +x $(EXT_CPY)



clean:
	rm -f $(OBJS) $(EXT_C) $(EXT_CPY) $(PYLIB) $(PYFULL) pyparsing.pyo

distclean:
	rm -f $(OBJS) $(EXT_C) $(EXT_CPY) $(PYLIB) $(PYFULL) pyparsing.pyo *~
