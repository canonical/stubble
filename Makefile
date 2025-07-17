# SPDX-License-Identifier: LGPL-2.1-or-later

include ./Make.defaults

ARCH=	?= $(shell uname -m)

ifeq ($(ARCH),x86_64)
	CFLAGS += -m64 -march=x86-64 -mno-red-zone -mgeneral-regs-only -maccumulate-outgoing-args
	LDFLAGS += -m64
endif
ifeq ($(ARCH),aarch64)
	CFLAGS += -mgeneral-regs-only
endif

OBJS = devicetree.o device-path-util.o efi-efivars.o efi-log.o efi-string.o export-vars.o linux.o \
    part-discovery.o pe.o shim.o splash.o string-util-fundamental.o stub.o  url-discovery.o util.o uki.o \
    random-seed.o smbios.o secure-boot.o initrd.o graphics.o efi-firmware.o chid.o \
    sha256.o console.o edid.o sha1.o \
    drivers.o

all: stub.efi

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

stub.efi: stub
	./elf2efi.py --version-major=6 --version-minor=16 --efi-major=1 --efi-minor=1 --subsystem=10 --copy-sections=".sbat,.sdmagic,.osrel" stub $@

stub: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS)
	rm -f stub
	rm -f stub.efi
