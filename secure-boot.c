/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "console.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "efi-string-table.h"
#include "proto/security-arch.h"
#include "secure-boot.h"
#include "util.h"
#include "vmm.h"

bool secure_boot_enabled(void) {
        bool secure = false;  /* avoid false maybe-uninitialized warning */
        EFI_STATUS err;

        err = efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"SecureBoot", &secure);

        return err == EFI_SUCCESS && secure;
}

/*
 * Custom mode allows the secure boot certificate databases db, dbx, KEK, and PK to be changed without the variable
 * updates being signed. When enrolling certificates to an unconfigured system (no PK present yet) writing
 * db, dbx and KEK updates without signature works fine even in standard mode. Writing PK updates without
 * signature requires custom mode in any case.
 *
 * Enabling custom mode works only if a user is physically present. Note that OVMF has a dummy
 * implementation for the user presence check (there is no useful way to implement a presence check for a
 * virtual machine).
 *
 * FYI: Your firmware setup utility might offers the option to enroll certificates from *.crt files
 * (DER-encoded x509 certificates) on the ESP; that uses custom mode too. Your firmware setup might also
 * offer the option to switch the system into custom mode for the next boot.
 */
static bool custom_mode_enabled(void) {
        bool enabled = false;

        (void) efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_CUSTOM_MODE_ENABLE),
                                     u"CustomMode", &enabled);
        return enabled;
}

static EFI_STATUS set_custom_mode(bool enable) {
        static char16_t name[] = u"CustomMode";
        static uint32_t attr =
                EFI_VARIABLE_NON_VOLATILE |
                EFI_VARIABLE_BOOTSERVICE_ACCESS;
        uint8_t mode = enable
                ? 1   /* CUSTOM_SECURE_BOOT_MODE   */
                : 0;  /* STANDARD_SECURE_BOOT_MODE */

        return RT->SetVariable(name, MAKE_GUID_PTR(EFI_CUSTOM_MODE_ENABLE),
                               attr, sizeof(mode), &mode);
}

static struct SecurityOverride {
        EFI_SECURITY_ARCH_PROTOCOL *security;
        EFI_SECURITY2_ARCH_PROTOCOL *security2;
        EFI_SECURITY_FILE_AUTHENTICATION_STATE original_hook;
        EFI_SECURITY2_FILE_AUTHENTICATION original_hook2;

        security_validator_t validator;
        const void *validator_ctx;
} security_override;

static EFIAPI EFI_STATUS security_hook(
                const EFI_SECURITY_ARCH_PROTOCOL *this,
                uint32_t authentication_status,
                const EFI_DEVICE_PATH *file) {

        assert(security_override.validator);
        assert(security_override.security);
        assert(security_override.original_hook);

        if (security_override.validator(security_override.validator_ctx, file, NULL, 0))
                return EFI_SUCCESS;

        return security_override.original_hook(security_override.security, authentication_status, file);
}

static EFIAPI EFI_STATUS security2_hook(
                const EFI_SECURITY2_ARCH_PROTOCOL *this,
                const EFI_DEVICE_PATH *device_path,
                void *file_buffer,
                size_t file_size,
                bool boot_policy) {

        assert(security_override.validator);
        assert(security_override.security2);
        assert(security_override.original_hook2);

        if (security_override.validator(security_override.validator_ctx, device_path, file_buffer, file_size))
                return EFI_SUCCESS;

        return security_override.original_hook2(
                        security_override.security2, device_path, file_buffer, file_size, boot_policy);
}

/* This replaces the platform provided security arch protocols hooks (defined in the UEFI Platform
 * Initialization Specification) with our own that uses the given validator to decide if a image is to be
 * trusted. If not running in secure boot or the protocols are not available nothing happens. The override
 * must be removed with uninstall_security_override() after LoadImage() has been called.
 *
 * This is a hack as we do not own the security protocol instances and modifying them is not an official part
 * of their spec. But there is little else we can do to circumvent secure boot short of implementing our own
 * PE loader. We could replace the firmware instances with our own instance using
 * ReinstallProtocolInterface(), but some firmware will still use the old ones. */
void install_security_override(security_validator_t validator, const void *validator_ctx) {
        EFI_STATUS err;

        assert(validator);

        if (!secure_boot_enabled())
                return;

        security_override = (struct SecurityOverride) {
                .validator = validator,
                .validator_ctx = validator_ctx,
        };

        EFI_SECURITY_ARCH_PROTOCOL *security = NULL;
        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_SECURITY_ARCH_PROTOCOL), NULL, (void **) &security);
        if (err == EFI_SUCCESS) {
                security_override.security = security;
                security_override.original_hook = security->FileAuthenticationState;
                security->FileAuthenticationState = security_hook;
        }

        EFI_SECURITY2_ARCH_PROTOCOL *security2 = NULL;
        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_SECURITY2_ARCH_PROTOCOL), NULL, (void **) &security2);
        if (err == EFI_SUCCESS) {
                security_override.security2 = security2;
                security_override.original_hook2 = security2->FileAuthentication;
                security2->FileAuthentication = security2_hook;
        }
}

void uninstall_security_override(void) {
        if (security_override.original_hook)
                security_override.security->FileAuthenticationState = security_override.original_hook;
        if (security_override.original_hook2)
                security_override.security2->FileAuthentication = security_override.original_hook2;
}

static const char *secure_boot_enroll_table[_SECURE_BOOT_ENROLL_MAX] = {
        [ENROLL_OFF]     = "off",
        [ENROLL_MANUAL]  = "manual",
        [ENROLL_IF_SAFE] = "if-safe",
        [ENROLL_FORCE]   = "force"
};

static const char *secure_boot_enroll_action_table[_SECURE_BOOT_ENROLL_ACTION_MAX] = {
        [ENROLL_ACTION_REBOOT]   = "reboot",
        [ENROLL_ACTION_SHUTDOWN] = "shutdown"
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(secure_boot_enroll, secure_boot_enroll);
DEFINE_STRING_TABLE_LOOKUP_TO_STRING(secure_boot_enroll_action, secure_boot_enroll_action);
