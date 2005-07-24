#############################################################################
#
# Zelkova - A Firewall and Intrusion Prevention System on Linux Kernel
#
# Copyright (C) 2005 Dongsu Park <advance@dongsu.pe.kr>
#
# Copyright (C) 1994, 1995-8, 1999, 2001 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.
#
#############################################################################

# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y

# Change it here or specify it on the "make" commandline
INCLUDEDIR = /usr/src/linux/include

ifeq ($(DEBUG),y)
	DEBFLAGS = -O -g -DZELKOVA_DEBUG
else
	DEBFLAGS = -O2
endif

WARN	:= -Wall
INCLUDE += -I$(INCLUDEDIR) -I./fistree
#INCLUDE += -isystem /lib/modules/`uname -r`/build/include

CFLAGS	:= -D__KERNEL__ -DMODULE -DEXPORT_SYMTAB ${WARN} ${DEBFLAGS} ${INCLUDE}

# Extract version number from headers
VER = $(shell awk -F\" '/REL/ {print $$2}' $(INCLUDEDIR)/linux/version.h)

TARGET := zelkova
OBJS = $(TARGET).o
SRC = main.c ioctl.c

all: .depend $(TARGET).o


$(TARGET).o: $(SRC:.c=.o)
	$(LD) -m elf_i386 -r $^ -o $@

install:
	mkdir -p /lib/modules/$(VER)/misc
	install -c $(TARGET).o /lib/modules/$(VER)/misc

.PHONY: clean

clean:
	rm -f *.o *~ core .depend

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > $@

ifeq (.depend,$(wildcard .depend))
include .depend
endif
