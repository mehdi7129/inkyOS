#ifndef INKY_AUTHOPEN_H
#define INKY_AUTHOPEN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Ask macOS to open an existing whole raw disk, and return its descriptor.
 * The caller remains unprivileged. No disk data is read or written here.
 *
 * path must be /dev/rdisk followed only by decimal digits. flags may contain
 * O_RDONLY or O_RDWR, optionally O_NOFOLLOW/O_NONBLOCK; creation, truncation,
 * append and advisory-lock flags are refused. authopen receives only the
 * access mode. A non-symlink character-device identity is checked before and
 * after receipt, and O_NONBLOCK/FD_CLOEXEC are applied to the returned fd.
 *
 * Returns -1 with a bounded diagnostic on failure. The caller owns a
 * successful fd and must close it. Authorization can wait up to 300 seconds.
 */
int inky_authopen(const char *path, int flags, char *error, size_t error_capacity);

#ifdef __cplusplus
}
#endif

#endif
