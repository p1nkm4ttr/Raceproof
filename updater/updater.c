/* RaceProof competing updater.
 *
 * Changes the target file while the broker is between check and launch.
 *
 *   updater --mode replace|rewrite --at <stage>|free --target <path> --payload <file>
 *           [--region header|text|tail | --offset N --len M] [--layout fixtures/layout.txt]
 *           [--alt <file>] [--interval-us lo:hi] [--once] [--quiet]
 *
 * replace  write the payload to a temp file in the target's directory, fsync, rename
 *          over the target. Atomic; the inode changes.
 * rewrite  open the target for writing and pwrite the payload's bytes [offset, offset+len)
 *          at the same offset into the same inode. If the kernel refuses because the
 *          file is being executed, errno is ETXTBSY and that is recorded, not hidden.
 *
 * --at <stage>  controlled: serve the barrier FIFOs in $RP_BARRIER_DIR. For every stage
 *          line the broker child sends, perform the write if the stage matches, then
 *          answer "go". Serves one broker child after another until killed (or one with
 *          --once).
 * --at free     uncontrolled: loop forever alternating the payload and --alt (default:
 *          the original target bytes) with a random sleep in [lo, hi] microseconds
 *          between writes. Killed by the harness.
 *
 * Every write emits one JSON line on stdout: action, offset, len, errno, errstr, t_us. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <libgen.h>
#include <sys/stat.h>

static const char *mode = NULL, *at = NULL, *target = NULL, *payload = NULL, *alt = NULL;
static const char *region = NULL, *layout = "fixtures/layout.txt";
static long offset = -1, len = -1, lo_us = 50, hi_us = 500;
static int once = 0, quiet = 0;
static unsigned char *pay = NULL, *altbuf = NULL; static long paylen = 0, altlen = 0;

static long now_us(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec * 1000000L + ts.tv_nsec / 1000; }

static unsigned char *slurp(const char *file, long *n) {
    int fd = open(file, O_RDONLY); if (fd < 0) { fprintf(stderr, "updater: open %s: %s\n", file, strerror(errno)); exit(2); }
    struct stat st; fstat(fd, &st);
    unsigned char *b = malloc(st.st_size ? st.st_size : 1); long got = 0; ssize_t r;
    while ((r = read(fd, b + got, st.st_size - got)) > 0) got += r;
    close(fd); *n = got; return b;
}

static void emit(const char *action, long off, long l, int err, long t) {
    if (quiet) return;
    printf("{\"action\":\"%s\",\"offset\":%ld,\"len\":%ld,\"errno\":%d,\"errstr\":\"%s\",\"t_us\":%ld}\n",
           action, off, l, err, err ? strerror(err) : "", t);
    fflush(stdout);
}

static int do_replace(const unsigned char *buf, long n) {
    char dir[4096]; strncpy(dir, target, sizeof dir - 1); dir[sizeof dir - 1] = 0;
    char tmp[4352]; snprintf(tmp, sizeof tmp, "%s/.rp_upd_%d", dirname(dir), getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0755); if (fd < 0) return errno;
    long w = 0; while (w < n) { ssize_t r = write(fd, buf + w, n - w); if (r < 0) { int e = errno; close(fd); unlink(tmp); return e; } w += r; }
    fsync(fd); close(fd);
    if (rename(tmp, target) < 0) { int e = errno; unlink(tmp); return e; }
    return 0;
}

static int do_rewrite(const unsigned char *buf, long n, long off, long l) {
    if (off + l > n) l = n - off;
    if (l <= 0) return EINVAL;
    int fd = open(target, O_WRONLY); if (fd < 0) return errno;     /* ETXTBSY lands here if running */
    long w = 0; while (w < l) { ssize_t r = pwrite(fd, buf + off + w, l - w, off + w); if (r < 0) { int e = errno; close(fd); return e; } w += r; }
    close(fd); return 0;
}

static void act(const unsigned char *buf, long n, const char *label) {
    long t0 = now_us(); int e;
    if (strcmp(mode, "replace") == 0) { e = do_replace(buf, n); emit(label, 0, n, e, now_us() - t0); }
    else { e = do_rewrite(buf, n, offset, len); emit(label, offset, len, e, now_us() - t0); }
}

static void resolve_region(void) {
    if (strcmp(mode, "rewrite") != 0) return;
    if (offset >= 0 && len > 0) return;
    if (!region) { fprintf(stderr, "updater: rewrite needs --region or --offset/--len\n"); exit(2); }
    long size = paylen, text_off = -1, text_size = -1;
    /* layout.txt lines: bin/prog_b_1m size=N text_off=N text_size=N pad=HEX */
    FILE *f = fopen(layout, "r");
    if (f) {
        char pb[4096]; strncpy(pb, payload, sizeof pb - 1); pb[sizeof pb - 1] = 0;
        const char *base = basename(pb);
        char line[1024];
        while (fgets(line, sizeof line, f)) {
            char name[512]; long s, to, ts;
            if (sscanf(line, "%511s size=%ld text_off=%ld text_size=%ld", name, &s, &to, &ts) == 4) {
                char nb[512]; strncpy(nb, name, sizeof nb); nb[sizeof nb - 1] = 0;
                if (strcmp(basename(nb), base) == 0) { size = s; text_off = to; text_size = ts; break; }
            }
        }
        fclose(f);
    }
    if (strcmp(region, "header") == 0) { offset = 0; len = 64; }
    else if (strcmp(region, "text") == 0) {
        if (text_off < 0) { fprintf(stderr, "updater: no layout entry for %s, cannot use --region text\n", payload); exit(2); }
        offset = text_off; len = text_size;
    } else if (strcmp(region, "tail") == 0) { len = size < 65536 ? size : 65536; offset = size - len; }
    else { fprintf(stderr, "updater: unknown region %s\n", region); exit(2); }
}

static void serve_barrier(void) {
    const char *dir = getenv("RP_BARRIER_DIR");
    if (!dir) { fprintf(stderr, "updater: --at <stage> needs RP_BARRIER_DIR\n"); exit(2); }
    char tp[4096], fp[4096];
    snprintf(tp, sizeof tp, "%s/to_updater", dir); snprintf(fp, sizeof fp, "%s/from_updater", dir);
    mkfifo(tp, 0600); mkfifo(fp, 0600);                 /* fine if they already exist */
    for (;;) {
        int to = open(tp, O_RDONLY); if (to < 0) { perror("updater: open to_updater"); exit(2); }
        int from = open(fp, O_WRONLY); if (from < 0) { perror("updater: open from_updater"); exit(2); }
        FILE *in = fdopen(to, "r"); char line[128];
        while (fgets(line, sizeof line, in)) {
            size_t L = strlen(line); while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
            if (strcmp(line, at) == 0) act(pay, paylen, mode);
            if (write(from, "go\n", 3) != 3) break;
        }
        fclose(in); close(from);
        if (once) break;
    }
}

static void run_free(void) {
    srand((unsigned)(now_us() ^ getpid()));
    for (;;) {
        act(pay, paylen, mode);
        usleep(lo_us + rand() % (hi_us - lo_us + 1));
        act(altbuf, altlen, strcmp(mode, "replace") == 0 ? "restore" : "rewrite_alt");
        usleep(lo_us + rand() % (hi_us - lo_us + 1));
    }
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        #define ARG(name, var) if (!strcmp(argv[i], name) && i + 1 < argc) { var = argv[++i]; continue; }
        ARG("--mode", mode) ARG("--at", at) ARG("--target", target) ARG("--payload", payload)
        ARG("--alt", alt) ARG("--region", region) ARG("--layout", layout)
        if (!strcmp(argv[i], "--offset") && i + 1 < argc) { offset = atol(argv[++i]); continue; }
        if (!strcmp(argv[i], "--len") && i + 1 < argc) { len = atol(argv[++i]); continue; }
        if (!strcmp(argv[i], "--interval-us") && i + 1 < argc) { sscanf(argv[++i], "%ld:%ld", &lo_us, &hi_us); continue; }
        if (!strcmp(argv[i], "--once")) { once = 1; continue; }
        if (!strcmp(argv[i], "--quiet")) { quiet = 1; continue; }
        fprintf(stderr, "updater: bad argument %s\n", argv[i]); return 2;
    }
    if (!mode || !at || !target || !payload || (strcmp(mode, "replace") && strcmp(mode, "rewrite"))) {
        fprintf(stderr, "usage: updater --mode replace|rewrite --at <stage>|free --target <path> --payload <file> "
                        "[--region header|text|tail | --offset N --len M] [--alt <file>] [--interval-us lo:hi] [--once] [--quiet]\n");
        return 2;
    }
    if (hi_us < lo_us) hi_us = lo_us;
    pay = slurp(payload, &paylen);
    resolve_region();
    if (strcmp(at, "free") == 0) {
        altbuf = slurp(alt ? alt : target, &altlen);   /* default: restore the original bytes */
        run_free();
    } else {
        serve_barrier();
    }
    return 0;
}
