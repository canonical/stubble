/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpio.h"
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
#include "vmm.h"

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
                EFI_STUB_FEATURE_CMDLINE_ADDONS |           /* We pick up .cmdline addons */
                EFI_STUB_FEATURE_CMDLINE_SMBIOS |           /* We support extending kernel cmdline from SMBIOS Type #11 */
                EFI_STUB_FEATURE_DEVICETREE_ADDONS |        /* We pick up .dtb addons */
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

static EFI_STATUS load_addons_from_dir(
                EFI_FILE *root,
                const char16_t *prefix,
                char16_t ***items,
                size_t *n_items,
                size_t *n_allocated) {

        _cleanup_file_close_ EFI_FILE *extra_dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *dirent = NULL;
        size_t dirent_size = 0;
        EFI_STATUS err;

        assert(root);
        assert(prefix);
        assert(items);
        assert(n_items);
        assert(n_allocated);

        err = open_directory(root, prefix, &extra_dir);
        if (err == EFI_NOT_FOUND)
                /* No extra subdir, that's totally OK */
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to open addons directory '%ls': %m", prefix);

        for (;;) {
                _cleanup_free_ char16_t *d = NULL;

                err = readdir(extra_dir, &dirent, &dirent_size);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to read addons directory of loaded image: %m");
                if (!dirent) /* End of directory */
                        break;

                if (dirent->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;
                if (!is_ascii(dirent->FileName))
                        continue;
                if (strlen16(dirent->FileName) > 255) /* Max filename size on Linux */
                        continue;
                if (!endswith_no_case(dirent->FileName, u".addon.efi"))
                        continue;

                d = xstrdup16(dirent->FileName);

                if (*n_items + 2 > *n_allocated) {
                        /* We allocate 16 entries at a time, as a matter of optimization */
                        if (*n_items > (SIZE_MAX / sizeof(uint16_t)) - 16) /* Overflow check, just in case */
                                return log_oom();

                        size_t m = *n_items + 16;
                        *items = xrealloc(*items, *n_allocated * sizeof(uint16_t *), m * sizeof(uint16_t *));
                        *n_allocated = m;
                }

                (*items)[(*n_items)++] = TAKE_PTR(d);
                (*items)[*n_items] = NULL; /* Let's always NUL terminate, to make freeing via strv_free() easy */
        }

        return EFI_SUCCESS;
}

static void cmdline_append_and_measure_addons(
                char16_t *cmdline_addon,
                char16_t **cmdline_append,
                int *parameters_measured) {

        assert(cmdline_append);
        assert(parameters_measured);

        if (isempty(cmdline_addon))
                return;

        _cleanup_free_ char16_t *copy = mangle_stub_cmdline(xstrdup16(cmdline_addon));
        if (isempty(copy))
                return;

        bool m = false;
        (void) tpm_log_load_options(copy, &m);
        combine_measured_flag(parameters_measured, m);

        _cleanup_free_ char16_t *tmp = TAKE_PTR(*cmdline_append);
        if (isempty(tmp))
                *cmdline_append = TAKE_PTR(copy);
        else
                *cmdline_append = xasprintf("%ls %ls", tmp, copy);
}

typedef struct NamedAddon {
        char16_t *filename;
        struct iovec blob;
} NamedAddon;

static void named_addon_done(NamedAddon *a) {
        assert(a);

        a->filename = mfree(a->filename);
        iovec_done(&a->blob);
}

static void named_addon_free_many(NamedAddon *a, size_t n) {
        assert(a || n == 0);

        FOREACH_ARRAY(i, a, n)
                named_addon_done(i);

        free(a);
}

static void install_addon_devicetrees(
                struct devicetree_state *dt_state,
                const NamedAddon *addons,
                size_t n_addons,
                int *parameters_measured) {

        EFI_STATUS err;

        assert(dt_state);
        assert(addons || n_addons == 0);
        assert(parameters_measured);

        FOREACH_ARRAY(a, addons, n_addons) {
                err = devicetree_install_from_memory(dt_state, a->blob.iov_base, a->blob.iov_len);
                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Error loading addon devicetree, ignoring: %m");
                        continue;
                }

                bool m = false;
                err = tpm_log_tagged_event(
                                TPM2_PCR_KERNEL_CONFIG,
                                POINTER_TO_PHYSICAL_ADDRESS(a->blob.iov_base),
                                a->blob.iov_len,
                                DEVICETREE_ADDON_EVENT_TAG_ID,
                                a->filename,
                                &m);
                if (err != EFI_SUCCESS)
                        return (void) log_error_status(
                                        err,
                                        "Unable to extend PCR %i with DTB addon '%ls': %m",
                                        TPM2_PCR_KERNEL_CONFIG,
                                        a->filename);

                combine_measured_flag(parameters_measured, m);
        }
}

static inline void iovec_array_extend(struct iovec **arr, size_t *n_arr, struct iovec elem) {
        assert(arr);
        assert(n_arr);

        if (!iovec_is_set(&elem))
                return;

        *arr = xrealloc(*arr, *n_arr * sizeof(struct iovec), (*n_arr + 1)  * sizeof(struct iovec));
        (*arr)[(*n_arr)++] = elem;
}

static EFI_STATUS load_addons(
                EFI_HANDLE stub_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *prefix,
                const char *uname,
                char16_t **cmdline,                         /* Both input+output, extended with new addons we find */
                NamedAddon **devicetree_addons,             /* Ditto */
                size_t *n_devicetree_addons) {

        _cleanup_strv_free_ char16_t **items = NULL;
        _cleanup_file_close_ EFI_FILE *root = NULL;
        size_t n_items = 0, n_allocated = 0;
        EFI_STATUS err;

        assert(stub_image);
        assert(loaded_image);
        assert(prefix);

        if (!loaded_image->DeviceHandle)
                return EFI_SUCCESS;

        err = open_volume(loaded_image->DeviceHandle, &root);
        if (err == EFI_UNSUPPORTED)
                /* Error will be unsupported if the bootloader doesn't implement the file system protocol on
                 * its file handles. */
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to open root directory: %m");

        err = load_addons_from_dir(root, prefix, &items, &n_items, &n_allocated);
        if (err != EFI_SUCCESS)
                return err;

        if (n_items == 0)
                return EFI_SUCCESS; /* Empty directory */

        /* Now, sort the files we found, to make this uniform and stable (and to ensure the TPM measurements
         * are not dependent on read order) */
        sort_pointer_array((void**) items, n_items, (compare_pointer_func_t) strcmp16);

        for (size_t i = 0; i < n_items; i++) {
                PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
                _cleanup_free_ EFI_DEVICE_PATH *addon_path = NULL;
                _cleanup_(unload_imagep) EFI_HANDLE addon = NULL;
                EFI_LOADED_IMAGE_PROTOCOL *loaded_addon = NULL;
                _cleanup_free_ char16_t *addon_spath = NULL;

                addon_spath = xasprintf("%ls\\%ls", prefix, items[i]);
                err = make_file_device_path(loaded_image->DeviceHandle, addon_spath, &addon_path);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Error making device path for %ls: %m", addon_spath);

                /* By using shim_load_image, we cover both the case where the PE files are signed with MoK
                 * and with DB, and running with or without shim. */
                err = shim_load_image(stub_image, addon_path, /* boot_policy= */ false, &addon);
                if (err != EFI_SUCCESS) {
                        log_error_status(err,
                                         "Failed to read '%ls' from '%ls', ignoring: %m",
                                         items[i],
                                         addon_spath);
                        continue;
                }

                err = BS->HandleProtocol(addon,
                                         MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL),
                                         (void **) &loaded_addon);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to find protocol in %ls: %m", items[i]);

                err = pe_memory_locate_sections(loaded_addon->ImageBase, unified_sections, sections);
                if (err != EFI_SUCCESS ||
                    (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE) &&
                     !PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB) &&
                     !PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTBAUTO))) {
                        if (err == EFI_SUCCESS)
                                err = EFI_NOT_FOUND;
                        log_error_status(err,
                                         "Unable to locate embedded .cmdline/.dtb/.dtbauto sections in %ls, ignoring: %m",
                                         items[i]);
                        continue;
                }

                /* We want to enforce that addons are not UKIs, i.e.: they must not embed a kernel. */
                if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_LINUX)) {
                        log_error("%ls is a UKI, not an addon, ignoring.", items[i]);
                        continue;
                }

                /* Also enforce that, in case it is specified, .uname matches as a quick way to allow
                 * enforcing compatibility with a specific UKI only */
                if (uname && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_UNAME) &&
                                !strneq8(uname,
                                         (const char *)loaded_addon->ImageBase + sections[UNIFIED_SECTION_UNAME].memory_offset,
                                         sections[UNIFIED_SECTION_UNAME].memory_size)) {
                        log_error(".uname mismatch between %ls and UKI, ignoring", items[i]);
                        continue;
                }

                if (cmdline && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE)) {
                        _cleanup_free_ char16_t *tmp = TAKE_PTR(*cmdline),
                                *extra16 = mangle_stub_cmdline(pe_section_to_str16(loaded_addon, sections + UNIFIED_SECTION_CMDLINE));

                        *cmdline = xasprintf("%ls%ls%ls", strempty(tmp), isempty(tmp) ? u"" : u" ", extra16);
                }

                // FIXME: do we want to do something else here?
                // This should behave exactly as .dtb/.dtbauto in the main UKI
                if (devicetree_addons && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTBAUTO)) {
                        *devicetree_addons = xrealloc(*devicetree_addons,
                                                      *n_devicetree_addons * sizeof(NamedAddon),
                                                      (*n_devicetree_addons + 1) * sizeof(NamedAddon));

                        (*devicetree_addons)[(*n_devicetree_addons)++] = (NamedAddon) {
                                .blob = {
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_DTBAUTO].memory_offset, sections[UNIFIED_SECTION_DTBAUTO].memory_size),
                                        .iov_len = sections[UNIFIED_SECTION_DTBAUTO].memory_size,
                                },
                                .filename = xstrdup16(items[i]),
                        };
                } else if (devicetree_addons && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB)) {
                        *devicetree_addons = xrealloc(*devicetree_addons,
                                                      *n_devicetree_addons * sizeof(NamedAddon),
                                                      (*n_devicetree_addons + 1) * sizeof(NamedAddon));

                        (*devicetree_addons)[(*n_devicetree_addons)++] = (NamedAddon) {
                                .blob = {
                                        .iov_base = xmemdup((const uint8_t*) loaded_addon->ImageBase + sections[UNIFIED_SECTION_DTB].memory_offset, sections[UNIFIED_SECTION_DTB].memory_size),
                                        .iov_len = sections[UNIFIED_SECTION_DTB].memory_size,
                                },
                                .filename = xstrdup16(items[i]),
                        };
                }
        }

        return EFI_SUCCESS;
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

static void cmdline_append_and_measure_smbios(char16_t **cmdline, int *parameters_measured) {
        assert(cmdline);
        assert(parameters_measured);

        const char *extra = smbios_find_oem_string("io.systemd.stub.kernel-cmdline-extra=", /* after= */ NULL);
        if (!extra)
                return;

        _cleanup_free_ char16_t *extra16 = mangle_stub_cmdline(xstr8_to_16(extra));
        if (isempty(extra16))
                return;

        /* SMBIOS strings are measured in PCR1, but we also want to measure them in our specific PCR12, as
         * firmware-owned PCRs are very difficult to use as they'll contain unpredictable measurements that
         * are not under control of the machine owner. */
        bool m = false;
        (void) tpm_log_load_options(extra16, &m);
        combine_measured_flag(parameters_measured, m);

        _cleanup_free_ char16_t *tmp = TAKE_PTR(*cmdline);
        if (isempty(tmp))
                *cmdline = TAKE_PTR(extra16);
        else
                *cmdline = xasprintf("%ls %ls", tmp, extra16);
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

static void load_all_addons(
                EFI_HANDLE image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char *uname,
                char16_t **cmdline_addons,
                NamedAddon **dt_addons,
                size_t *n_dt_addons) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(cmdline_addons);
        assert(dt_addons);
        assert(n_dt_addons);

        err = load_addons(
                        image,
                        loaded_image,
                        u"\\loader\\addons",
                        uname,
                        cmdline_addons,
                        dt_addons,
                        n_dt_addons);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading global addons, ignoring: %m");

        /* Some bootloaders always pass NULL in FilePath, so we need to check for it here. */
        _cleanup_free_ char16_t *dropin_dir = get_extra_dir(loaded_image->FilePath);
        if (!dropin_dir)
                return;

        err = load_addons(
                        image,
                        loaded_image,
                        dropin_dir,
                        uname,
                        cmdline_addons,
                        dt_addons,
                        n_dt_addons);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading UKI-specific addons, ignoring: %m");
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
        _cleanup_free_ char16_t *cmdline = NULL, *cmdline_addons = NULL;
        struct iovec initrd = {};
        PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_free_ char *uname = NULL;
        NamedAddon *dt_addons = NULL;
        size_t n_dt_addons = 0;
        EFI_STATUS err;

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        /* Pick up the arguments passed to us, and return the rest
         * as potential command line to use. */
        (void) process_arguments(image, loaded_image, &cmdline);

        /* Find the sections we want to operate on */
        err = find_sections(loaded_image, sections);
        if (err != EFI_SUCCESS)
                return err;

        measure_sections(loaded_image, sections, &sections_measured);

        refresh_random_seed(loaded_image);

        uname = pe_section_to_str8(loaded_image, sections + UNIFIED_SECTION_UNAME);

        /* Now that we have the UKI sections loaded, also load global first and then local (per-UKI)
         * addons. The data is loaded at once, and then used later. */
        CLEANUP_ARRAY(dt_addons, n_dt_addons, named_addon_free_many);
        load_all_addons(image, loaded_image, uname, &cmdline_addons, &dt_addons, &n_dt_addons);

        /* If we have any extra command line to add via PE addons, load them now and append, and measure the
         * additions together, after the embedded options, but before the smbios ones, so that the order is
         * reversed from "most hardcoded" to "most dynamic". The global addons are loaded first, and the
         * image-specific ones later, for the same reason. */
        cmdline_append_and_measure_addons(cmdline_addons, &cmdline, &parameters_measured);
        cmdline_append_and_measure_smbios(&cmdline, &parameters_measured);

        export_common_variables(loaded_image);
        export_stub_variables(loaded_image);

        /* First load the base device tree, then fix it up using addons - global first, then per-UKI. */
        install_embedded_devicetree(loaded_image, sections, &dt_state);
        install_addon_devicetrees(&dt_state, dt_addons, n_dt_addons, &parameters_measured);

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
