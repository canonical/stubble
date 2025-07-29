# SPDX-License-Identifier: LGPL-2.1-or-later

include ./Make.defaults

ARCH?=		$(shell uname -m)
PREFIX?=	/usr

ifeq ($(ARCH),x86_64)
	CFLAGS += -m64 -march=x86-64 -mno-red-zone -mgeneral-regs-only -maccumulate-outgoing-args
	LDFLAGS += -m64
endif
ifeq ($(ARCH),aarch64)
	CFLAGS += -mgeneral-regs-only
endif

OBJS = devicetree.o device-path-util.o efi-efivars.o efi-log.o \
    efi-string.o export-vars.o linux.o part-discovery.o pe.o shim.o \
    string-util-fundamental.o stub.o  url-discovery.o util.o uki.o \
    random-seed.o smbios.o secure-boot.o initrd.o efi-firmware.o chid.o \
    sha256.o console.o edid.o sha1.o

.PHONY: all clean install

all: ubustub.efi

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

ubustub.efi: ubustub
	./elf2efi.py --version-major=6 --version-minor=16 \
	    --efi-major=1 --efi-minor=1 --subsystem=10 \
	    --minimum-sections=50 \
	    --copy-sections=".sbat,.sdmagic,.osrel" $< $@

ubustub: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

install: ubustub.efi
	install -m 755 -d ${DESTDIR}${PREFIX}/lib/ubustub
	install -m 644 -t ${DESTDIR}${PREFIX}/lib/ubustub ubustub.efi
	install -m 755 -d ${DESTDIR}${PREFIX}/share/ubustub/hwids
	install -m 644 -t ${DESTDIR}${PREFIX}/share/ubustub/hwids hwids/json/*

clean:
	rm -f $(OBJS)
	rm -f ubustub
	rm -f ubustub.efi
