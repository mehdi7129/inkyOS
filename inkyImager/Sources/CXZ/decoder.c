#include "CXZ.h"
#include <lzma.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(char *dst, size_t cap, const char *text) {
    if (cap) snprintf(dst, cap, "%s", text);
    return -1;
}

int inky_xz_decode(int source_fd, int output_fd, uint64_t output_limit,
                   inky_xz_progress progress, void *context,
                   char *error_buffer, size_t error_capacity) {
    unsigned char input[65536], output[65536];
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_ret code = lzma_stream_decoder(&stream, 128ULL * 1024 * 1024, 0);
    if (code != LZMA_OK) return fail(error_buffer, error_capacity, "Impossible de préparer le décodeur XZ.");
    int result = -1, input_eof = 0;
    uint64_t total = 0;
    while (1) {
        if (!stream.avail_in && !input_eof) {
            ssize_t count;
            do { count = read(source_fd, input, sizeof(input)); } while (count < 0 && errno == EINTR);
            if (count < 0) { fail(error_buffer, error_capacity, "Lecture de l’image impossible."); break; }
            input_eof = count == 0;
            stream.next_in = input;
            stream.avail_in = count > 0 ? (size_t)count : 0;
        }
        stream.next_out = output;
        stream.avail_out = sizeof(output);
        code = lzma_code(&stream, input_eof ? LZMA_FINISH : LZMA_RUN);
        size_t produced = sizeof(output) - stream.avail_out;
        if (produced > output_limit || total > output_limit - produced) {
            fail(error_buffer, error_capacity, "L’image dépasse la taille annoncée."); break;
        }
        size_t done = 0;
        while (done < produced) {
            ssize_t count = write(output_fd, output + done, produced - done);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { fail(error_buffer, error_capacity, "Écriture de l’image impossible."); goto cleanup; }
            done += (size_t)count;
        }
        total += produced;
        if (progress && produced) progress(total, context);
        if (code == LZMA_STREAM_END) {
            unsigned char extra;
            ssize_t count;
            do { count = read(source_fd, &extra, 1); } while (count < 0 && errno == EINTR);
            if (stream.avail_in || count != 0) { fail(error_buffer, error_capacity, "Données inattendues après l’image XZ."); break; }
            if (total != output_limit) { fail(error_buffer, error_capacity, "L’image est incomplète."); break; }
            result = 0; break;
        }
        if (code != LZMA_OK || (input_eof && !produced)) {
            fail(error_buffer, error_capacity, "L’image XZ est incomplète ou endommagée."); break;
        }
    }
cleanup:
    lzma_end(&stream);
    return result;
}
