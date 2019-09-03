# -*- makefile -*-
#
# Copyright (c) 2019 Canonical Ltd.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

# The architecture of the host CPU
HOST_CPU := $(shell dpkg-architecture -q DEB_HOST_GNU_CPU)

# The currently installed crash version and the temporary crash build directory
CRASH_VERSION := $(shell crash --version | \
	awk '$$1 == "crash" { print $$2; exit; }')
CRASH_DIR ?= $(CURDIR)/.crash/$(CRASH_VERSION)/$(HOST_CPU)

all: extension

crash: $(CRASH_DIR)/crash
$(CRASH_DIR)/crash:
	rm -rf $(CRASH_DIR)
	git clone --depth 1 --branch $(CRASH_VERSION) \
		https://github.com/crash-utility/crash.git $(CRASH_DIR)
	$(MAKE) -C $(CRASH_DIR)

extension: $(CRASH_DIR)/crash
	$(MAKE) -C Extension -f Makefile.shared CRASH_DIR=$(CRASH_DIR)

clean:
	rm -rf $(CRASH_DIR)
	$(MAKE) -C Extension -f Makefile.shared clean
