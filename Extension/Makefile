#
# Before running make, use 'configure' utility

INSTALL := /usr/bin/install

# This is a directory where extension file will be copied
DESTDIR := /usr/local/lib
DIRMODE= 755

DEBUG =  -g

# Check whether we ran configure

c_ok := $(wildcard crash.mk)

ifeq ($(strip $(c_ok)),)
not_configured:
	@echo "You need to configure the directories before running make"
	@exit 1
else
  include crash.mk local.mk
endif


INCLUDES := -I$(CRASHDIR) $(PYINCLUDE)
DEFINES += -D$(TARGET) -DCRASHVERS=\"$(CRASHVERS)\"

# Older 'make' does not support 'else ifeq'

EXT = mpykdump.so


all: $(EXT)



.PHONY: clean distclean install

%o: %c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) $< -o $@

gdbspec.o: gdbspec.c
	$(CC) -c $(CFLAGS) $(GDBINCL) $(PYINCLUDE) $(EXTRA)  $< -o $@

OBJS :=  epython.o functions.o gdbspec.o

$(EXT): $(OBJS)
	$(CC) -shared  $(LINKFLAGS)  $^ -o $@  $(LIBS)

install: $(EXT)
	if test ! -d $(DESTDIR); then \
		echo "Creating directory $(DESTDIR)"; \
		$(INSTALL) -d -m $(DIRMODE) $(DESTDIR); \
	fi;
	$(INSTALL) $(EXT) $(DESTDIR)

all: $(EXT)


clean:
	rm -f $(OBJS) $(EXT)


distclean:
	rm -f $(OBJS) $(EXT) *.mk *~ *.so
