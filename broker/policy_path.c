/* Pathname policy (the vulnerable baseline).
 * Hash the file at a path, close it, then execve that same path. Anything that
 * replaces or rewrites the path between the hash and the exec wins. */
#define _GNU_SOURCE
#include "policy.h"
#include "barrier.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

void policy_path(const char *path, char **argv) {
    struct status st; memset(&st, 0, sizeof st);
    st.torn_first = st.torn_last = -1;

    barrier_stage("pre_hash");
    long t0 = now_us();
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || !elf_magic_ok(fd) || hash_fd(fd, st.observed_hex, &st.bytes_hashed) < 0) {
        st.decision = 1; st.t_check_us = now_us() - t0;
        send_status(&st); _exit(3);
    }
    close(fd);                                   /* the check is over; only the name remains */
    st.t_check_us = now_us() - t0;
    st.decision = allowlist_has(st.observed_hex) ? 0 : 1;
    send_status(&st);
    if (st.decision) _exit(3);

    barrier_stage("post_hash");
    apply_gap();
    execve(path, argv, environ);                 /* resolves the name again: the race */
    st.exec_errno = errno;
    send_status(&st);
    _exit(127);
}
