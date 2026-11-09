/* Open-descriptor policy.
 * Open once, hash through the descriptor, exec that same descriptor with
 * execveat(AT_EMPTY_PATH). A pathname replacement cannot reach it; an in-place
 * write to the same inode still can. */
#define _GNU_SOURCE
#include "policy.h"
#include "barrier.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>

void policy_fd(const char *path, char **argv) {
    struct status st; memset(&st, 0, sizeof st);
    st.torn_first = st.torn_last = -1;

    barrier_stage("pre_hash");
    long t0 = now_us();
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { st.decision = RP_ERROR; st.exec_errno = errno; send_status(&st); _exit(EXIT_ERROR); }
    if (!elf_magic_ok(fd)) { st.decision = RP_REJECT; st.t_check_us = now_us() - t0; send_status(&st); _exit(EXIT_REJECT); }
    if (hash_fd(fd, st.observed_hex, &st.bytes_hashed) < 0) { st.decision = RP_ERROR; st.exec_errno = errno; send_status(&st); _exit(EXIT_ERROR); }
    st.t_check_us = now_us() - t0;
    st.decision = allowlist_has(st.observed_hex) ? RP_APPROVE : RP_REJECT;
    send_status(&st);
    if (st.decision) _exit(EXIT_REJECT);

    barrier_stage("post_hash");
    apply_gap();
    syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH);   /* same file object we hashed */
    st.exec_errno = errno;
    send_status(&st);
    _exit(127);
}
