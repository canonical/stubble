/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "proto/device-path.h"
#include "util.h"

EFI_STATUS make_file_device_path(EFI_HANDLE device, const char16_t *file, EFI_DEVICE_PATH **ret_dp) {
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        assert(file);
        assert(ret_dp);

        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
        if (err != EFI_SUCCESS)
                return err;

        EFI_DEVICE_PATH *end_node = dp;
        while (!IsDevicePathEnd(end_node))
                end_node = NextDevicePathNode(end_node);

        size_t file_size = strsize16(file);
        size_t dp_size = (uint8_t *) end_node - (uint8_t *) dp;

        /* Make a copy that can also hold a file media device path. */
        *ret_dp = xmalloc(dp_size + file_size + sizeof(FILEPATH_DEVICE_PATH) + sizeof(EFI_DEVICE_PATH));
        dp = mempcpy(*ret_dp, dp, dp_size);

        /* Replace end node with file media device path. Use memcpy() in case dp is unaligned (if accessed as
         * FILEPATH_DEVICE_PATH). */
        dp->Type = MEDIA_DEVICE_PATH;
        dp->SubType = MEDIA_FILEPATH_DP;
        dp->Length = sizeof(FILEPATH_DEVICE_PATH) + file_size;
        memcpy((uint8_t *) dp + sizeof(FILEPATH_DEVICE_PATH), file, file_size);

        dp = NextDevicePathNode(dp);
        SetDevicePathEndNode(dp);
        return EFI_SUCCESS;
}

EFI_STATUS device_path_to_str(const EFI_DEVICE_PATH *dp, char16_t **ret) {
        EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dp_to_text;
        EFI_STATUS err;
        _cleanup_free_ char16_t *str = NULL;

        assert(dp);
        assert(ret);

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_DEVICE_PATH_TO_TEXT_PROTOCOL), NULL, (void **) &dp_to_text);
        if (err != EFI_SUCCESS) {
                /* If the device path to text protocol is not available we can still do a best-effort attempt
                 * to convert it ourselves if we are given filepath-only device path. */

                size_t size = 0;
                for (const EFI_DEVICE_PATH *node = dp; !IsDevicePathEnd(node);
                     node = NextDevicePathNode(node)) {

                        if (DevicePathType(node) != MEDIA_DEVICE_PATH ||
                            DevicePathSubType(node) != MEDIA_FILEPATH_DP)
                                return err;

                        size_t path_size = DevicePathNodeLength(node);
                        if (path_size <= offsetof(FILEPATH_DEVICE_PATH, PathName) || path_size % sizeof(char16_t))
                                return EFI_INVALID_PARAMETER;
                        path_size -= offsetof(FILEPATH_DEVICE_PATH, PathName);

                        _cleanup_free_ char16_t *old = str;
                        str = xmalloc(size + path_size);
                        if (old) {
                                memcpy(str, old, size);
                                str[size / sizeof(char16_t) - 1] = '\\';
                        }

                        memcpy(str + (size / sizeof(char16_t)),
                               ((uint8_t *) node) + offsetof(FILEPATH_DEVICE_PATH, PathName),
                               path_size);
                        size += path_size;
                }

                *ret = TAKE_PTR(str);
                return EFI_SUCCESS;
        }

        str = dp_to_text->ConvertDevicePathToText(dp, false, false);
        if (!str)
                return EFI_OUT_OF_RESOURCES;

        *ret = TAKE_PTR(str);
        return EFI_SUCCESS;
}

bool device_path_startswith(const EFI_DEVICE_PATH *dp, const EFI_DEVICE_PATH *start) {
        if (!start)
                return true;
        if (!dp)
                return false;
        for (;;) {
                if (IsDevicePathEnd(start))
                        return true;
                if (IsDevicePathEnd(dp))
                        return false;
                size_t l1 = DevicePathNodeLength(start);
                size_t l2 = DevicePathNodeLength(dp);
                if (l1 != l2)
                        return false;
                if (memcmp(dp, start, l1) != 0)
                        return false;
                start = NextDevicePathNode(start);
                dp = NextDevicePathNode(dp);
        }
}

EFI_DEVICE_PATH *device_path_replace_node(
                const EFI_DEVICE_PATH *path, const EFI_DEVICE_PATH *node, const EFI_DEVICE_PATH *new_node) {

        /* Create a new device path as a copy of path, while chopping off the remainder starting at the given
         * node. If new_node is provided, it is appended at the end of the new path. */

        assert(path);
        assert(node);

        size_t len = (uint8_t *) node - (uint8_t *) path, new_node_len = 0;
        if (new_node)
                new_node_len = DevicePathNodeLength(new_node);

        EFI_DEVICE_PATH *ret = xmalloc(len + new_node_len + sizeof(EFI_DEVICE_PATH));
        EFI_DEVICE_PATH *end = mempcpy(ret, path, len);

        if (new_node)
                end = mempcpy(end, new_node, new_node_len);

        SetDevicePathEndNode(end);
        return ret;
}
