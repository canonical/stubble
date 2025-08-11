/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Generic Linux boot protocol using the EFI/PE entry point of the kernel. Passes
 * initrd with the LINUX_INITRD_MEDIA_GUID DevicePath and cmdline with
 * EFI LoadedImageProtocol.
 *
 * This method works for Linux 5.8 and newer on ARM/Aarch64, x86/x68_64 and RISC-V.
 */

#include "efi-log.h"
#include "initrd.h"
#include "linux.h"
#include "pe.h"
#include "proto/device-path.h"
#include "proto/loaded-image.h"
#include "util.h"

typedef struct {
        MEMMAP_DEVICE_PATH memmap_path;
        EFI_DEVICE_PATH end_path;
} _packed_ KERNEL_FILE_PATH;

EFI_STATUS linux_exec(
                EFI_HANDLE parent_image,
                const char16_t *cmdline,
                const struct iovec *kernel,
                const struct iovec *initrd) {

        size_t kernel_size_in_memory = 0;
        uint32_t entry_point;
        uint64_t image_base;
        EFI_STATUS err;

        assert(parent_image);
        assert(iovec_is_set(kernel));
        assert(iovec_is_valid(initrd));

        err = pe_kernel_info(kernel->iov_base, &entry_point, &image_base, &kernel_size_in_memory);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Bad kernel image: %m");

        /* Re-use the parent_image(_handle) and parent_loaded_image for the kernel image we are about to execute.
         * We have to do this, because if kernel stub code passes its own handle to certain firmware functions,
         * the firmware could cast EFI_LOADED_IMAGE_PROTOCOL * to a larger struct to access its own private data,
         * and if we allocated a smaller struct, that could cause problems.
         * This is modeled exactly after GRUB behaviour, which has proven to be functional. */
        EFI_LOADED_IMAGE_PROTOCOL* parent_loaded_image;
        err = BS->HandleProtocol(
                        parent_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &parent_loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot get parent loaded image: %m");

        err = pe_kernel_check_no_relocation(kernel->iov_base);
        if (err != EFI_SUCCESS)
                return err;

        const PeSectionHeader *headers;
        size_t n_headers;

        /* Do we need to validate anything here? the len? */
        err = pe_section_table_from_base(kernel->iov_base, &headers, &n_headers);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot read sections: %m");

        /* Do we need to ensure under 4gb address on x86? */
        _cleanup_pages_ Pages loaded_kernel_pages = xmalloc_pages(
                        AllocateAnyPages, EfiLoaderCode, EFI_SIZE_TO_PAGES(kernel_size_in_memory), 0);

        uint8_t* loaded_kernel = PHYSICAL_ADDRESS_TO_POINTER(loaded_kernel_pages.addr);
        FOREACH_ARRAY(h, headers, n_headers) {
                if (h->PointerToRelocations != 0)
                        return log_error_status(EFI_LOAD_ERROR, "Inner kernel image contains sections with relocations, which we do not support.");
                if (h->SizeOfRawData == 0)
                        continue;

                if ((h->VirtualAddress < image_base)
                    || (h->VirtualAddress - image_base + h->SizeOfRawData > kernel_size_in_memory))
                        return log_error_status(EFI_LOAD_ERROR, "Section would write outside of memory");
                memcpy(loaded_kernel + h->VirtualAddress - image_base,
                       (const uint8_t*)kernel->iov_base + h->PointerToRawData,
                       h->SizeOfRawData);
                memzero(loaded_kernel + h->VirtualAddress + h->SizeOfRawData,
                        h->VirtualSize - h->SizeOfRawData);
        }

        _cleanup_free_ KERNEL_FILE_PATH *kernel_file_path = xnew(KERNEL_FILE_PATH, 1);

        kernel_file_path->memmap_path.Header.Type = HARDWARE_DEVICE_PATH;
        kernel_file_path->memmap_path.Header.SubType = HW_MEMMAP_DP;
        kernel_file_path->memmap_path.Header.Length = sizeof (MEMMAP_DEVICE_PATH);
        kernel_file_path->memmap_path.MemoryType = EfiLoaderData;
        kernel_file_path->memmap_path.StartingAddress = POINTER_TO_PHYSICAL_ADDRESS(kernel->iov_base);
        kernel_file_path->memmap_path.EndingAddress = POINTER_TO_PHYSICAL_ADDRESS(kernel->iov_base) + kernel->iov_len;

        kernel_file_path->end_path.Type = END_DEVICE_PATH_TYPE;
        kernel_file_path->end_path.SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
        kernel_file_path->end_path.Length = sizeof (EFI_DEVICE_PATH);

        parent_loaded_image->ImageBase = loaded_kernel;
        parent_loaded_image->ImageSize = kernel_size_in_memory;

        if (cmdline) {
                parent_loaded_image->LoadOptions = (void *) cmdline;
                parent_loaded_image->LoadOptionsSize = strsize16(parent_loaded_image->LoadOptions);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd->iov_base, initrd->iov_len, &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error registering initrd: %m");

        log_wait();

        EFI_IMAGE_ENTRY_POINT entry =
                (EFI_IMAGE_ENTRY_POINT) ((const uint8_t *) parent_loaded_image->ImageBase + entry_point);
        err = entry(parent_image, ST);

        return log_error_status(err, "Error starting kernel image: %m");
}
