# SPDX-License-Identifier: LGPL-2.1-or-later

# # DEBUG
# CFLAGS += -O0 -g

# # Unused
# CFLAGS += -ffunction-sections
# LDFLAGS += -Wl,--gc-sections
# LDFLAGS += -Wl,--print-gc-sections

CFLAGS += -I include
CFLAGS += -DRELATIVE_SOURCE_PATH="\".\""
CFLAGS += -fno-strict-aliasing
CFLAGS += -ffreestanding
CFLAGS += -fshort-wchar
CFLAGS += -fwide-exec-charset=UCS2
CFLAGS += -maccumulate-outgoing-args
CFLAGS += -mstack-protector-guard=global
CFLAGS += -DCOLOR_NORMAL=0x0f
CFLAGS += -fno-lto
CFLAGS += '-DEFI_MACHINE_TYPE_NAME="x64"'
CFLAGS += '-DGIT_VERSION="1.0-ubuntu0"'

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
LDFLAGS += $(shell $(CC) -print-libgcc-file-name)
LDFLAGS += -Wl,-z,nopack-relative-relocs
LDFLAGS += -fcf-protection=none
LDFLAGS += -fno-asynchronous-unwind-tables
LDFLAGS += -fno-exceptions -fno-unwind-tables
LDFLAGS += -fno-lto

# arch specific stuff
CFLAGS += -m64 -march=x86-64 -mno-red-zone -mgeneral-regs-only
LDFLAGS += -m64

OBJS = cpio.o devicetree.o device-path-util.o efi-efivars.o efi-log.o efi-string.o export-vars.o linux.o \
    part-discovery.o pe.o shim.o splash.o string-util-fundamental.o stub.o  url-discovery.o util.o uki.o \
    random-seed.o smbios.o secure-boot.o initrd.o graphics.o efi-firmware.o chid.o \
    sha256-fundamental.o console.o vmm.o edid.o sha1-fundamental.o \
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
