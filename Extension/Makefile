#
# Copy this file to Makefile and edit the copy as needed. If you have Python-2.4
# and its development packages installed properly, you only need to customize
# the next line (CRASH sources location)

INSTALL := /usr/bin/install

# This is a directory where extension file will be copied
DESTDIR := /usr/local/lib
DIRMODE= 755

ifdef STATICBUILD
  DEFINES := -DSTATICBUILD
  buildtype := --static
endif

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
DEFINES += -D$(TARGET)


# Older 'make' does not support 'else ifeq'

EXT = mpykdump64.so


ifeq ($(TARGET),X86)
  EXT = mpykdump32.so
endif

ifeq ($(TARGET),X86_64)
  EXT = mpykdump64.so
endif


all: $(EXT)



.PHONY: clean distclean install

%o: %c
	$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) $< -o $@

gdbspec.o: gdbspec.c
	$(CC) -c $(CFLAGS) $(GDBINCL) $(PYINCLUDE)  $< -o $@

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
	rm -f $(OBJS) $(EXT) *.mk *~
