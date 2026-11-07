/* Sealed-copy policy.
 *
 * Copy the file into a private memfd, seal it against write/shrink/grow, hash the
 * sealed bytes, compare with the allowlist, and execveat the memfd. Nothing that
 * happens to the original file after the copy can reach what runs. The copy
 * itself is the remaining window: a write that lands mid-copy produces a memfd
 * holding part old, part new content (a torn copy). The post-seal hash is what
 * must catch it.
 *
 * Order matters: copy, then seal, then validate, then execute.
 *
 * Stages: pre_hash (before the copy starts), mid_copy (after RP_TEAR_AT bytes,
 * default half the file), post_seal (after sealing, before the hash).
 *
 * Instrumentation (controlled matrix only): if RP_REF_A and RP_REF_B name the
 * two fixture files, the child compares the sealed copy against both after the
 * decision and reports torn / torn_first / torn_last. That comparison costs
 * time, so t_pre_exec_us is reported excluding it; the overhead matrix runs
 * without RP_REF_* set and is unaffected. */
#define _GNU_SOURCE
#include "policy.h"
#include "barrier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#define RP_SEALS (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL)
#define CHUNK 65536

static int make_memfd(void) {
    int m = syscall(SYS_memfd_create, "raceproof", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
    if (m < 0 && errno == EINVAL)                 /* kernel before 6.3: MFD_EXEC unknown, exec allowed by default */
        m = syscall(SYS_memfd_create, "raceproof", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    return m;
}

/* Copy src into mfd. Fires the mid_copy stage once exactly tear_at bytes are in. */
static long copy_with_tear(int src, int mfd, long tear_at) {
    unsigned char buf[CHUNK]; long copied = 0; int fired = 0; ssize_t n;
    for (;;) {
        size_t want = CHUNK;
        if (!fired && tear_at >= 0 && copied < tear_at && (long)want > tear_at - copied) want = tear_at - copied;
        if (!fired && tear_at >= 0 && copied >= tear_at) { barrier_stage("mid_copy"); fired = 1; }
        n = read(src, buf, want);
        if (n < 0) return -1;
        if (n == 0) break;
        long w = 0; while (w < n) { ssize_t r = write(mfd, buf + w, n - w); if (r < 0) return -1; w += r; }
        copied += n;
    }
    if (!fired && tear_at >= 0) barrier_stage("mid_copy");   /* tear point beyond EOF: fire at the end */
    return copied;
}

/* Compare the sealed copy with reference A and B; set torn fields. */
static void torn_analysis(int mfd, long len, struct status *st) {
    const char *ra = getenv("RP_REF_A"), *rb = getenv("RP_REF_B");
    if (!ra || !rb) return;
    int fa = open(ra, O_RDONLY | O_CLOEXEC), fb = open(rb, O_RDONLY | O_CLOEXEC);
    if (fa < 0 || fb < 0) return;
    unsigned char m[CHUNK], a[CHUNK], b[CHUNK];
    int all_a = 1, all_b = 1; long first = -1, last = -1;
    for (off_t off = 0; off < len; off += CHUNK) {
        ssize_t nm = pread(mfd, m, CHUNK, off), na = pread(fa, a, CHUNK, off), nb = pread(fb, b, CHUNK, off);
        if (nm <= 0) break;
        if (na != nm || memcmp(m, a, nm) != 0) {
            all_a = 0;
            for (ssize_t i = 0; i < nm; i++) if (i >= na || m[i] != a[i]) { if (first < 0) first = off + i; last = off + i; }
        }
        if (nb != nm || memcmp(m, b, nm) != 0) all_b = 0;
    }
    close(fa); close(fb);
    st->torn = (!all_a && !all_b);
    st->torn_first = all_a ? -1 : first;
    st->torn_last = all_a ? -1 : last;
}

void policy_sealed(const char *path, char **argv) {
    struct status st; memset(&st, 0, sizeof st);
    st.torn_first = st.torn_last = -1;

    barrier_stage("pre_hash");
    long t0 = now_us();
    int src = open(path, O_RDONLY | O_CLOEXEC);
    if (src < 0) { st.decision = 1; send_status(&st); _exit(3); }
    struct stat sb; fstat(src, &sb);

    long tear_at = -1;
    const char *env = getenv("RP_TEAR_AT");
    if (getenv("RP_BARRIER_DIR")) tear_at = (env && *env) ? atol(env) : sb.st_size / 2;

    int mfd = make_memfd();
    if (mfd < 0) { st.decision = 1; st.exec_errno = errno; send_status(&st); _exit(3); }

    long copied = copy_with_tear(src, mfd, tear_at);
    close(src);                                      /* the original is never touched again */
    if (copied < 0) { st.decision = 1; send_status(&st); _exit(3); }
    st.bytes_copied = copied;

    if (fcntl(mfd, F_ADD_SEALS, RP_SEALS) < 0) { st.decision = 1; st.exec_errno = errno; send_status(&st); _exit(3); }
    int seals = fcntl(mfd, F_GET_SEALS);
    st.seal_ok = (seals >= 0 && (seals & RP_SEALS) == RP_SEALS);
    st.t_copy_us = now_us() - t0;
    barrier_stage("post_seal");

    long t1 = now_us();
    if (!st.seal_ok || !elf_magic_ok(mfd) || hash_fd(mfd, st.observed_hex, &st.bytes_hashed) < 0) {
        st.decision = 1; st.t_check_us = now_us() - t1;
        torn_analysis(mfd, copied, &st);
        send_status(&st); _exit(3);
    }
    st.t_check_us = now_us() - t1;
    st.decision = allowlist_has(st.observed_hex) ? 0 : 1;
    torn_analysis(mfd, copied, &st);                 /* instrumentation; not part of the decision */
    send_status(&st);
    if (st.decision) _exit(3);

    apply_gap();
    syscall(SYS_execveat, mfd, "", argv, environ, AT_EMPTY_PATH);   /* the sealed bytes we hashed */
    st.exec_errno = errno;
    send_status(&st);
    _exit(127);
}
