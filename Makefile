# SPDX-License-Identifier: LGPL-2.1-or-later

CFLAGS += -DRELATIVE_SOURCE_PATH="\".\""
CFLAGS += -DGIT_VERSION=\"1\"
CFLAGS += -fno-strict-aliasing
CFLAGS += -ffreestanding
CFLAGS += -fshort-wchar
CFLAGS += -I include
CFLAGS += -fwide-exec-charset=UCS2
CFLAGS += -maccumulate-outgoing-args
CFLAGS += -mstack-protector-guard=global
CFLAGS += -DCOLOR_NORMAL=0x0f
CFLAGS += -fno-lto
CFLAGS += -DEFI_MACHINE_TYPE_NAME=\"x86-64\"

LDFLAGS += -nostdlib
LDFLAGS += -static-pie
LDFLAGS += -Wl,--entry=efi_main
LDFLAGS += -Wl,--fatal-warnings
LDFLAGS += -Wl,-static,-pie,--no-dynamic-linker,-z,text
LDFLAGS += -z common-page-size=4096
LDFLAGS += -z max-page-size=4096
LDFLAGS += -z noexecstack
LDFLAGS += -z relro
LDFLAGS += -z separate-code
LDFLAGS += -fno-lto
LDFLAGS += $(shell $(CC) -print-libgcc-file-name)

# arch specific stuff
CFLAGS += -m64 -march=x86-64 -mno-red-zone -mgeneral-regs-only
LDFLAGS += -m64

OBJS = cpio.o devicetree.o device-path-util.o efi-efivars.o efi-log.o efi-string.o export-vars.o linux.o \
    part-discovery.o pe.o shim.o splash.o string-util-fundamental.o stub.o  url-discovery.o util.o uki.o \
    random-seed.o smbios.o secure-boot.o initrd.o ticks.o graphics.o linux_x86.o efi-firmware.o chid.o \
    sha256-fundamental.o efivars-fundamental.o console.o vmm.o edid.o chid-fundamental.o sha1-fundamental.o \
    drivers.o edid-fundamental.o

all: stub.efi

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

stub.efi: stub
	./elf2efi.py stub $@

stub: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS)
	rm -f stub
	rm -f stub.efi
