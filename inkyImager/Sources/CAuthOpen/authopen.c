#include "CAuthOpen.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void message(char *error, size_t capacity, const char *text) {
    if (error && capacity) snprintf(error, capacity, "%s", text);
}

static int fail(char *error, size_t capacity, const char *text, int code) {
    message(error, capacity, text);
    errno = code;
    return -1;
}

static double monotonic_seconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

/* Keep spawn source descriptors clear of stdin/stdout/stderr, even if the
 * calling process originally had one of its standard descriptors closed. */
static int private_descriptor(int *descriptor) {
    if (*descriptor < 3) {
        int replacement = fcntl(*descriptor, F_DUPFD_CLOEXEC, 3);
        if (replacement < 0) return -1;
        close(*descriptor);
        *descriptor = replacement;
    }
    return fcntl(*descriptor, F_SETFD, FD_CLOEXEC);
}

static void terminate_child(pid_t child) {
    if (child <= 0) return;
    int status;
    pid_t result;
    do { result = waitpid(child, &status, WNOHANG); } while (result < 0 && errno == EINTR);
    if (result == child || (result < 0 && errno == ECHILD)) return;
    kill(child, SIGTERM);
    const struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000000 };
    nanosleep(&pause, NULL);
    do { result = waitpid(child, &status, WNOHANG); } while (result < 0 && errno == EINTR);
    if (result == 0) {
        kill(child, SIGKILL);
        do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    }
}

static int wait_for_child(pid_t child, double deadline, int *status) {
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 0;
        if (result < 0 && errno != EINTR) return -1;
        double now = monotonic_seconds();
        if (now < 0 || now >= deadline) { errno = ETIMEDOUT; return -1; }
        const struct timespec pause = { .tv_sec = 0, .tv_nsec = 20000000 };
        nanosleep(&pause, NULL);
    }
}

static void child_diagnostic(int descriptor, int status, char *error, size_t capacity) {
    char detail[2049] = {0};
    if (lseek(descriptor, 0, SEEK_SET) >= 0) {
        size_t used = 0;
        while (used < sizeof(detail) - 1) {
            ssize_t count = read(descriptor, detail + used, sizeof(detail) - 1 - used);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            used += (size_t)count;
        }
        while (used && (detail[used - 1] == '\n' || detail[used - 1] == '\r')) detail[--used] = 0;
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (error && capacity) {
        snprintf(error, capacity, "macOS n’a pas autorisé l’accès à la carte (authopen, code %d).%s%s",
                 code, detail[0] ? "\n" : "", detail);
    }
}

int inky_authopen(const char *path, int flags, char *error, size_t error_capacity) {
    message(error, error_capacity, "");
    const char prefix[] = "/dev/rdisk";
    if (!path || strncmp(path, prefix, sizeof(prefix) - 1) != 0 || !path[sizeof(prefix) - 1])
        return fail(error, error_capacity, "Chemin de carte SD invalide.", EINVAL);
    for (const char *p = path + sizeof(prefix) - 1; *p; ++p) {
        if (*p < '0' || *p > '9') return fail(error, error_capacity, "Choisissez une carte entière.", EINVAL);
    }
    const int access = flags & O_ACCMODE;
    if ((access != O_RDONLY && access != O_RDWR) ||
        (flags & ~(O_ACCMODE | O_NOFOLLOW | O_NONBLOCK)) != 0)
        return fail(error, error_capacity, "Mode d’accès à la carte invalide.", EINVAL);

    struct stat before;
    if (lstat(path, &before) != 0 || !S_ISCHR(before.st_mode) || before.st_uid != 0)
        return fail(error, error_capacity, "La carte sélectionnée n’est plus disponible.", ENODEV);

    int sockets[2] = {-1, -1}, diagnostic = -1, input = -1, received = -1;
    pid_t child = -1;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    bool actions_ready = false, attributes_ready = false;
    int saved_error = EIO;
    const char *failure = "Impossible de préparer l’autorisation macOS.";

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) goto cleanup;
    if (private_descriptor(&sockets[0]) != 0 || private_descriptor(&sockets[1]) != 0) goto cleanup;
    char temporary[] = "/private/tmp/inkyimager-authopen.XXXXXX";
    diagnostic = mkstemp(temporary);
    if (diagnostic < 0) goto cleanup;
    if (unlink(temporary) != 0) goto cleanup;
    if (fchmod(diagnostic, 0600) != 0 || private_descriptor(&diagnostic) != 0) goto cleanup;
    input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (input < 0 || private_descriptor(&input) != 0) goto cleanup;

    int spawn_error = posix_spawn_file_actions_init(&actions);
    if (spawn_error) { errno = spawn_error; goto cleanup; }
    actions_ready = true;
#define ACTION(call) do { spawn_error = (call); if (spawn_error) { errno = spawn_error; goto cleanup; } } while (0)
    ACTION(posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO));
    ACTION(posix_spawn_file_actions_adddup2(&actions, sockets[1], STDOUT_FILENO));
    ACTION(posix_spawn_file_actions_adddup2(&actions, diagnostic, STDERR_FILENO));
    ACTION(posix_spawn_file_actions_addclose(&actions, sockets[0]));
    ACTION(posix_spawn_file_actions_addclose(&actions, sockets[1]));
    ACTION(posix_spawn_file_actions_addclose(&actions, input));
    ACTION(posix_spawn_file_actions_addclose(&actions, diagnostic));
    ACTION(posix_spawnattr_init(&attributes));
    attributes_ready = true;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    ACTION(posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT));
#endif
#undef ACTION
    char mode[16];
    snprintf(mode, sizeof(mode), "%d", access);
    /* authopen's accepted flag set is narrower than open(2). In particular,
     * passing O_NOFOLLOW is refused on current macOS. Only request mode0/2;
     * the protected /dev path and device identities are checked on both sides. */
    char *const arguments[] = {"/usr/libexec/authopen", "-stdoutpipe", "-o", mode, (char *)path, NULL};
    char *const environment[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", NULL};
    double now = monotonic_seconds();
    if (now < 0) goto cleanup;
    const double deadline = now + 300.0;
    spawn_error = posix_spawn(&child, arguments[0], &actions, &attributes, arguments, environment);
    if (spawn_error) { errno = spawn_error; child = -1; goto cleanup; }
    close(sockets[1]); sockets[1] = -1;
    close(input); input = -1;

    failure = "macOS n’a pas transmis l’accès à la carte.";
    for (;;) {
        now = monotonic_seconds();
        if (now < 0 || now >= deadline) {
            failure = "L’autorisation macOS a expiré. Réessayez depuis inkyImager.";
            errno = ETIMEDOUT; goto cleanup;
        }
        struct pollfd channel = {.fd = sockets[0], .events = POLLIN};
        int ready = poll(&channel, 1, 500);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) goto cleanup;
        if (!ready) continue;
        if (channel.revents & POLLNVAL) { errno = EBADF; goto cleanup; }
        if (!(channel.revents & (POLLIN | POLLHUP | POLLERR))) continue;

        char payload = 0;
        struct iovec vector = {.iov_base = &payload, .iov_len = 1};
        union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int) * 8)]; } control;
        memset(&control, 0, sizeof(control));
        struct msghdr response = {0};
        response.msg_iov = &vector; response.msg_iovlen = 1;
        response.msg_control = control.bytes; response.msg_controllen = sizeof(control.bytes);
        ssize_t count = recvmsg(sockets[0], &response, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto cleanup;
        size_t descriptor_count = 0;
        bool malformed = (response.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0;
        for (struct cmsghdr *item = CMSG_FIRSTHDR(&response); item; item = CMSG_NXTHDR(&response, item)) {
            size_t remaining = response.msg_controllen - (size_t)((char *)item - control.bytes);
            if (remaining < sizeof(*item) || item->cmsg_len < CMSG_LEN(0) || item->cmsg_len > remaining) {
                malformed = true; break;
            }
            size_t length = item->cmsg_len - CMSG_LEN(0);
            if (item->cmsg_level != SOL_SOCKET || item->cmsg_type != SCM_RIGHTS || length % sizeof(int)) {
                malformed = true; continue;
            }
            for (size_t offset = 0; offset + sizeof(int) <= length; offset += sizeof(int)) {
                int descriptor;
                memcpy(&descriptor, (char *)CMSG_DATA(item) + offset, sizeof(descriptor));
                ++descriptor_count;
                if (received < 0) received = descriptor;
                else close(descriptor);
            }
        }
        if (malformed || descriptor_count != 1 || count != 1) {
            // A normal authorization refusal sends EOF, with its reason in stderr.
            if (count == 0 && descriptor_count == 0 && !malformed) break;
            errno = EPROTO; goto cleanup;
        }
        break;
    }

    // authopen keeps stdout open until its receiving peer closes the channel.
    // The descriptor itself is now independent of this socket. Close the
    // channel before waiting for the helper, as Raspberry Pi Imager does.
    close(sockets[0]); sockets[0] = -1;

    int status = 0;
    if (wait_for_child(child, deadline, &status) != 0) {
        if (errno == ETIMEDOUT) failure = "L’autorisation macOS a expiré. Réessayez depuis inkyImager.";
        goto cleanup;
    }
    child = -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        child_diagnostic(diagnostic, status, error, error_capacity);
        saved_error = EACCES;
        goto cleanup_preserving_message;
    }
    if (received < 0) { errno = EPROTO; goto cleanup; }
    struct stat opened, after;
    int actual_flags = fcntl(received, F_GETFL);
    if (actual_flags < 0 || (actual_flags & O_ACCMODE) != access ||
        fstat(received, &opened) != 0 || lstat(path, &after) != 0 ||
        !S_ISCHR(opened.st_mode) || !S_ISCHR(after.st_mode) || after.st_uid != 0 ||
        before.st_rdev != opened.st_rdev || before.st_rdev != after.st_rdev ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino) {
        failure = "La carte a changé pendant l’autorisation macOS.";
        errno = ENODEV; goto cleanup;
    }
    if (fcntl(received, F_SETFD, FD_CLOEXEC) != 0 ||
        ((flags & O_NONBLOCK) && fcntl(received, F_SETFL, actual_flags | O_NONBLOCK) != 0)) goto cleanup;

    if (attributes_ready) posix_spawnattr_destroy(&attributes);
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    close(diagnostic);
    return received;

cleanup:
    saved_error = errno ? errno : EIO;
    message(error, error_capacity, failure);
cleanup_preserving_message:
    if (child > 0) terminate_child(child);
    if (received >= 0) close(received);
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    if (diagnostic >= 0) close(diagnostic);
    if (input >= 0) close(input);
    if (attributes_ready) posix_spawnattr_destroy(&attributes);
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    errno = saved_error;
    return -1;
}
