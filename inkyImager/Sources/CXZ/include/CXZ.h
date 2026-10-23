#ifndef INKY_CXZ_H
#define INKY_CXZ_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef void (*inky_xz_progress)(uint64_t output_bytes, void *context);
/* Decodes exactly one XZ stream. Refuses trailing data and output beyond limit. */
int inky_xz_decode(int source_fd, int output_fd, uint64_t output_limit,
                   inky_xz_progress progress, void *context,
                   char *error_buffer, size_t error_capacity);
#ifdef __cplusplus
}
#endif
#endif
