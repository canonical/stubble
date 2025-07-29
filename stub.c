/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "devicetree.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "export-vars.h"
#include "iovec-util-fundamental.h"
#include "linux.h"
#include "measure.h"
#include "memory-util-fundamental.h"
#include "part-discovery.h"
#include "pe.h"
#include "proto/shell-parameters.h"
#include "random-seed.h"
#include "sbat.h"
#include "secure-boot.h"
#include "shim.h"
#include "smbios.h"
#include "tpm2-pcr.h"
#include "uki.h"
#include "url-discovery.h"
#include "util.h"
#include "version.h"

/* magic string to find in the binary image */
DECLARE_NOALLOC_SECTION(".sdmagic", "#### LoaderInfo: ubustub " GIT_VERSION " ####");

DECLARE_SBAT(SBAT_STUB_SECTION_TEXT);

static char16_t* pe_section_to_str16(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *section) {

        assert(loaded_image);
        assert(section);

        if (!PE_SECTION_VECTOR_IS_SET(section))
                return NULL;

        return xstrn8_to_16((const char *) loaded_image->ImageBase + section->memory_offset, section->memory_size);
}

static char *pe_section_to_str8(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *section) {

        assert(loaded_image);
        assert(section);

        if (!PE_SECTION_VECTOR_IS_SET(section))
                return NULL;

        return xstrndup8((const char *)loaded_image->ImageBase + section->memory_offset, section->memory_size);
}

static void combine_measured_flag(int *value, int measured) {
        assert(value);

        /* Combine the "measured" flag in a sensible way: if we haven't measured anything yet, the first
         * write is taken as is. Later writes can only turn off the flag, never on again. Or in other words,
         * we eventually want to return true iff we really measured *everything* there was to measure.
         *
         * Reminder how the "measured" flag actually works:
         *    > 0 → something was measured
         *   == 0 → there was something to measure but we didn't (because no TPM or so)
         *    < 0 → nothing has been submitted for measurement so far
         */

        if (measured < 0)
                return;

        *value = *value < 0 ? measured : *value && measured;
}

static void export_stub_variables(EFI_LOADED_IMAGE_PROTOCOL *loaded_image) {
        static const uint64_t stub_features =
                EFI_STUB_FEATURE_REPORT_BOOT_PARTITION |    /* We set LoaderDevicePartUUID */
                EFI_STUB_FEATURE_THREE_PCRS |               /* We can measure kernel image, parameters and sysext */
                EFI_STUB_FEATURE_RANDOM_SEED |              /* We pass a random seed to the kernel */
                EFI_STUB_FEATURE_REPORT_STUB_PARTITION |    /* We set StubDevicePartUUID + StubImageIdentifier */
                EFI_STUB_FEATURE_REPORT_URL |               /* We set StubDeviceURL + LoaderDeviceURL */
                0;

        assert(loaded_image);

        /* add StubInfo (this is one is owned by the stub, hence we unconditionally override this with our
         * own data) */
        (void) efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubInfo", u"ubustub " GIT_VERSION, 0);

        (void) efivar_set_uint64_le(MAKE_GUID_PTR(LOADER), u"StubFeatures", stub_features, 0);

        if (loaded_image->DeviceHandle) {
                _cleanup_free_ char16_t *uuid = disk_get_part_uuid(loaded_image->DeviceHandle);
                if (uuid)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubDevicePartUUID", uuid, 0);

                _cleanup_free_ char16_t *url = disk_get_url(loaded_image->DeviceHandle);
                if (url)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubDeviceURL", url, 0);
        }

        if (loaded_image->FilePath) {
                _cleanup_free_ char16_t *s = NULL;
                if (device_path_to_str(loaded_image->FilePath, &s) == EFI_SUCCESS)
                        efivar_set_str16(MAKE_GUID_PTR(LOADER), u"StubImageIdentifier", s, 0);
        }
}

static void parse_cmdline(char16_t *p) {

        assert(p);

        while (*p != '\0') {
                const char16_t *debug = L"debug";
                size_t debug_len = strlen16(debug);
                if (strncmp16(p, debug, debug_len) == 0 &&
                                (p[debug_len] == ' ' ||
                                 p[debug_len] == '\0'))
                        log_isdebug = true;

                p = strchr16(p, ' ');
                if (p == NULL)
                        return;
                p++;
        }
}

static void process_arguments(
                EFI_HANDLE stub_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                char16_t **ret_cmdline) {

        assert(stub_image);
        assert(loaded_image);
        assert(ret_cmdline);

        /* The UEFI shell registers EFI_SHELL_PARAMETERS_PROTOCOL onto images it runs. This lets us know that
         * LoadOptions starts with the stub binary path which we want to strip off. */
        EFI_SHELL_PARAMETERS_PROTOCOL *shell;
        if (BS->HandleProtocol(stub_image, MAKE_GUID_PTR(EFI_SHELL_PARAMETERS_PROTOCOL), (void **) &shell) != EFI_SUCCESS) {

                /* We also do a superficial check whether first character of passed command line
                 * is printable character (for compat with some Dell systems which fill in garbage?). */
                if (loaded_image->LoadOptionsSize < sizeof(char16_t) || ((const char16_t *) loaded_image->LoadOptions)[0] <= 0x1F)
                        goto nothing;

                /* Not running from EFI shell, use entire LoadOptions. Note that LoadOptions is a void*, so
                 * it could actually be anything! */
                char16_t *c = xstrndup16(loaded_image->LoadOptions, loaded_image->LoadOptionsSize / sizeof(char16_t));
                *ret_cmdline = mangle_stub_cmdline(c);
                return;
        }

        if (shell->Argc <= 1) /* No arguments were provided? Then we fall back to built-in cmdline. */
                goto nothing;

        size_t i = 1;

        if (i < shell->Argc) {
                /* Assemble the command line ourselves without our stub path. */
                *ret_cmdline = xstrdup16(shell->Argv[i++]);
                for (; i < shell->Argc; i++) {
                        _cleanup_free_ char16_t *old = *ret_cmdline;
                        *ret_cmdline = xasprintf("%ls %ls", old, shell->Argv[i]);
                }
        } else
                *ret_cmdline = NULL;

        return;

nothing:
        *ret_cmdline = NULL;
        return;
}

static inline void iovec_array_extend(struct iovec **arr, size_t *n_arr, struct iovec elem) {
        assert(arr);
        assert(n_arr);

        if (!iovec_is_set(&elem))
                return;

        *arr = xrealloc(*arr, *n_arr * sizeof(struct iovec), (*n_arr + 1)  * sizeof(struct iovec));
        (*arr)[(*n_arr)++] = elem;
}

static void refresh_random_seed(EFI_LOADED_IMAGE_PROTOCOL *loaded_image) {
        EFI_STATUS err;

        assert(loaded_image);

        /* Handle case, where bootloader doesn't support DeviceHandle. */
        if (!loaded_image->DeviceHandle)
                return;

        /* Don't measure again, if sd-boot already initialized the random seed */
        uint64_t loader_features = 0;
        (void) efivar_get_uint64_le(MAKE_GUID_PTR(LOADER), u"LoaderFeatures", &loader_features);
        if (FLAGS_SET(loader_features, EFI_LOADER_FEATURE_RANDOM_SEED))
                return;

        _cleanup_file_close_ EFI_FILE *esp_dir = NULL;
        err = partition_open(MAKE_GUID_PTR(ESP), loaded_image->DeviceHandle, NULL, &esp_dir);
        if (err != EFI_SUCCESS) /* Non-fatal on failure, so that we still boot without it. */
                return;

        (void) process_random_seed(esp_dir);
}

static void measure_sections(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                int *sections_measured) {

        assert(loaded_image);
        assert(sections);
        assert(sections_measured);

        /* Measure all "payload" of this PE image into a separate PCR (i.e. where nothing else is written
         * into so far), so that we have one PCR that we can nicely write policies against because it
         * contains all static data of this image, and thus can be easily be pre-calculated. */
        for (UnifiedSection section = 0; section < _UNIFIED_SECTION_MAX; section++) {

                if (!unified_section_measure(section)) /* shall not measure? */
                        continue;

                if (!PE_SECTION_VECTOR_IS_SET(sections + section)) /* not found */
                        continue;

                /* First measure the name of the section */
                bool m = false;
                (void) tpm_log_ipl_event_ascii(
                                TPM2_PCR_KERNEL_BOOT,
                                POINTER_TO_PHYSICAL_ADDRESS(unified_sections[section]),
                                strsize8(unified_sections[section]), /* including NUL byte */
                                unified_sections[section],
                                &m);
                combine_measured_flag(sections_measured, m);

                /* Then measure the data of the section */
                m = false;
                (void) tpm_log_ipl_event_ascii(
                                TPM2_PCR_KERNEL_BOOT,
                                POINTER_TO_PHYSICAL_ADDRESS(loaded_image->ImageBase) + sections[section].memory_offset,
                                sections[section].memory_size,
                                unified_sections[section],
                                &m);
                combine_measured_flag(sections_measured, m);
        }
}

static void export_pcr_variables(
                int sections_measured,
                int parameters_measured,
                int sysext_measured,
                int confext_measured) {

        /* After we are done with measuring, set an EFI variable that tells userspace this was done
         * successfully, and encode in it which PCR was used. */

        if (sections_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrKernelImage", TPM2_PCR_KERNEL_BOOT, 0);
        if (parameters_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrKernelParameters", TPM2_PCR_KERNEL_CONFIG, 0);
        if (sysext_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrInitRDSysExts", TPM2_PCR_SYSEXTS, 0);
        if (confext_measured > 0)
                (void) efivar_set_uint64_str16(MAKE_GUID_PTR(LOADER), u"StubPcrInitRDConfExts", TPM2_PCR_KERNEL_CONFIG, 0);
}

static void install_embedded_devicetree(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                struct devicetree_state *dt_state) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(sections);
        assert(dt_state);

        UnifiedSection section = _UNIFIED_SECTION_MAX;

        /* Use automatically selected DT if available, otherwise go for "normal" one */
        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTBAUTO))
                section = UNIFIED_SECTION_DTBAUTO;
        else if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB))
                section = UNIFIED_SECTION_DTB;
        else
                return;

        err = devicetree_install_from_memory(
                        dt_state,
                        (const uint8_t*) loaded_image->ImageBase + sections[section].memory_offset,
                        sections[section].memory_size);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading embedded devicetree, ignoring: %m");
}

static EFI_STATUS find_sections(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                PeSectionVector sections[static _UNIFIED_SECTION_MAX]) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(sections);

        const PeSectionHeader *section_table;
        size_t n_section_table;
        err = pe_section_table_from_base(loaded_image->ImageBase, &section_table, &n_section_table);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to locate PE section table: %m");

        /* Get the base sections */
        pe_locate_sections(
                    section_table,
                    n_section_table,
                    unified_sections,
                    /* validate_base= */ PTR_TO_SIZE(loaded_image->ImageBase),
                    sections);

        if (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_LINUX))
                return log_error_status(EFI_NOT_FOUND, "Image lacks .linux section.");

        return EFI_SUCCESS;
}

static EFI_STATUS run(EFI_HANDLE image) {
        int sections_measured = -1, parameters_measured = -1, sysext_measured = -1, confext_measured = -1;
        _cleanup_(devicetree_cleanup) struct devicetree_state dt_state = {};
        _cleanup_free_ char16_t *cmdline = NULL;
        struct iovec initrd = {};
        PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_free_ char *uname = NULL;
        EFI_STATUS err;

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        /* Pick up the arguments passed to us, and return the rest
         * as potential command line to use. */
        (void) process_arguments(image, loaded_image, &cmdline);
        parse_cmdline(cmdline);

        /* Find the sections we want to operate on */
        err = find_sections(loaded_image, sections);
        if (err != EFI_SUCCESS)
                return err;

        measure_sections(loaded_image, sections, &sections_measured);

        refresh_random_seed(loaded_image);

        uname = pe_section_to_str8(loaded_image, sections + UNIFIED_SECTION_UNAME);

        export_common_variables(loaded_image);
        export_stub_variables(loaded_image);

        /* Load the base device tree. */
        install_embedded_devicetree(loaded_image, sections, &dt_state);

        /* Find initrd if there is a .initrd section */
        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_INITRD))
                initrd = IOVEC_MAKE(
                                (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_INITRD].memory_offset,
                                sections[UNIFIED_SECTION_INITRD].memory_size);

        /* Export variables indicating what we measured */
        export_pcr_variables(sections_measured, parameters_measured, sysext_measured, confext_measured);

        struct iovec kernel = IOVEC_MAKE(
                        (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_LINUX].memory_offset,
                        sections[UNIFIED_SECTION_LINUX].memory_size);

        err = linux_exec(image, cmdline, &kernel, &initrd);
        return err;
}

DEFINE_EFI_MAIN_FUNCTION(run, "ubustub", /* wait_for_debugger= */ false);
