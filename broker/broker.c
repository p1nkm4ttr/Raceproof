/* RaceProof trusted broker.
 *
 * Reads tool requests from stdin, one per line:  RUN <path> [args...]
 * For each request it forks, applies the chosen launch policy in the child, and
 * prints one JSON line describing what happened: the decision, what actually ran
 * (the launched program's output), timings, and errors. The parent never trusts
 * the child's claim; it reads the launched program's own output.
 *
 * Usage: broker --policy path|fd|sealed [--allowlist file] [--timeout-ms N]
 * Environment: RP_BARRIER_DIR (see barrier.h), RP_GAP_US (sleep between hash and
 * exec, default 0), RP_TEAR_AT (sealed policy: bytes copied before mid_copy stage).
 */
#define _GNU_SOURCE
#include "policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include "sha256.h"

#define MAX_ALLOW 256
static char allow[MAX_ALLOW][65];
static int n_allow = 0;
static int status_fd = -1;
static long gap_us = 0;

long now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000L + ts.tv_nsec / 1000;
}

int allowlist_has(const char *hex) {
    for (int i = 0; i < n_allow; i++) if (strcmp(allow[i], hex) == 0) return 1;
    return 0;
}

int hash_fd(int fd, char hex[65], long *bytes) {
    sha256_ctx c; sha256_init(&c);
    unsigned char buf[65536]; off_t off = 0; ssize_t n; long total = 0;
    while ((n = pread(fd, buf, sizeof buf, off)) > 0) { sha256_update(&c, buf, n); off += n; total += n; }
    if (n < 0) return -1;
    unsigned char d[32]; sha256_final(&c, d); sha256_hex(d, hex);
    if (bytes) *bytes = total;
    return 0;
}

int elf_magic_ok(int fd) {
    unsigned char m[4];
    return pread(fd, m, 4, 0) == 4 && m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F';
}

void send_status(const struct status *st) {
    if (status_fd >= 0) { ssize_t r = write(status_fd, st, sizeof *st); (void)r; }
}

void apply_gap(void) { if (gap_us > 0) usleep(gap_us); }

static int load_allowlist(const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) { fprintf(stderr, "broker: cannot open allowlist %s: %s\n", file, strerror(errno)); return -1; }
    char line[4096];
    while (fgets(line, sizeof line, f) && n_allow < MAX_ALLOW) {
        if (strlen(line) < 64) continue;
        int ok = 1;
        for (int i = 0; i < 64; i++) if (!strchr("0123456789abcdef", line[i])) { ok = 0; break; }
        if (!ok) continue;
        memcpy(allow[n_allow], line, 64); allow[n_allow][64] = 0; n_allow++;
    }
    fclose(f);
    return n_allow;
}

static void json_str(FILE *o, const char *s) {
    fputc('"', o);
    for (; *s; s++) {
        unsigned char c = *s;
        if (c == '"' || c == '\\') { fputc('\\', o); fputc(c, o); }
        else if (c == '\n') fputs("\\n", o);
        else if (c < 0x20) fprintf(o, "\\u%04x", c);
        else fputc(c, o);
    }
    fputc('"', o);
}

static void run_one(const char *policy, char **argv, int timeout_ms) {
    const char *path = argv[0];
    int sp[2], op[2];
    if (pipe2(sp, O_CLOEXEC) < 0 || pipe2(op, O_CLOEXEC) < 0) { perror("pipe"); return; }

    long t_req = now_us();
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return; }
    if (pid == 0) {
        close(sp[0]); close(op[0]);
        dup2(op[1], 1); close(op[1]);        /* the launched program's stdout comes back to us */
        status_fd = sp[1];
        if (strcmp(policy, "path") == 0) policy_path(path, argv);
        else if (strcmp(policy, "fd") == 0) policy_fd(path, argv);
        else policy_sealed(path, argv);
        _exit(122);
    }
    close(sp[1]); close(op[1]);

    /* Read the launched program's output until EOF, noting the first byte's time. */
    char out[4096]; size_t outlen = 0; long t_first = -1;
    struct timespec deadline; clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000; deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
    int timed_out = 0;
    for (;;) {
        fd_set rf; FD_ZERO(&rf); FD_SET(op[0], &rf);
        struct timespec nowts; clock_gettime(CLOCK_MONOTONIC, &nowts);
        long rem_ms = (deadline.tv_sec - nowts.tv_sec) * 1000 + (deadline.tv_nsec - nowts.tv_nsec) / 1000000;
        if (rem_ms <= 0) { timed_out = 1; kill(pid, SIGKILL); break; }
        struct timeval tv = { rem_ms / 1000, (rem_ms % 1000) * 1000 };
        int r = select(op[0] + 1, &rf, NULL, NULL, &tv);
        if (r <= 0) continue;
        ssize_t n = read(op[0], out + outlen, sizeof out - 1 - outlen);
        if (n <= 0) break;
        if (t_first < 0) t_first = now_us();
        outlen += n;
        if (outlen >= sizeof out - 1) break;
    }
    out[outlen] = 0;
    close(op[0]);

    int wstatus = 0; struct rusage ru; memset(&ru, 0, sizeof ru);
    wait4(pid, &wstatus, 0, &ru);
    long t_end = now_us();

    /* Last status record wins (the child sends one after the decision, another on exec failure). */
    struct status st; memset(&st, 0, sizeof st); st.decision = -1; st.torn_first = st.torn_last = -1;
    struct status tmp; int got = 0;
    while (read(sp[0], &tmp, sizeof tmp) == (ssize_t)sizeof tmp) { st = tmp; got = 1; }
    close(sp[0]);

    int exit_status = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
    int sig = WIFSIGNALED(wstatus) ? WTERMSIG(wstatus) : 0;
    const char *decision = !got ? "NONE" : st.decision == 0 ? "APPROVE" : "REJECT";

    /* Trim trailing newline for a cleaner record. */
    while (outlen && (out[outlen-1] == '\n' || out[outlen-1] == '\r')) out[--outlen] = 0;

    printf("{\"policy\":\"%s\",\"path\":", policy); json_str(stdout, path);
    printf(",\"observed_hash\":\"%s\",\"allowlisted\":%s,\"decision\":\"%s\"",
           st.observed_hex, (got && st.decision == 0) ? "true" : "false", decision);
    printf(",\"exec_errno\":%d,\"exec_errstr\":", st.exec_errno); json_str(stdout, st.exec_errno ? strerror(st.exec_errno) : "");
    printf(",\"exit_status\":%d,\"signal\":%d,\"timed_out\":%d,\"child_output\":", exit_status, sig, timed_out); json_str(stdout, out);
    printf(",\"t_check_us\":%ld,\"t_copy_us\":%ld,\"t_total_us\":%ld,\"t_wait_us\":%ld",
           st.t_check_us, st.t_copy_us, t_first < 0 ? -1 : t_first - t_req, t_end - t_req);
    printf(",\"bytes_hashed\":%ld,\"bytes_copied\":%ld,\"peak_rss_kb\":%ld", st.bytes_hashed, st.bytes_copied, ru.ru_maxrss);
    printf(",\"seal_ok\":%d,\"torn\":%d,\"torn_first\":%ld,\"torn_last\":%ld,\"gap_us\":%ld}\n",
           st.seal_ok, st.torn, st.torn_first, st.torn_last, gap_us);
    fflush(stdout);
}

int main(int argc, char **argv) {
    const char *policy = NULL, *allowfile = "fixtures/allowlist.txt";
    int timeout_ms = 5000;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--policy") && i + 1 < argc) policy = argv[++i];
        else if (!strcmp(argv[i], "--allowlist") && i + 1 < argc) allowfile = argv[++i];
        else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else { fprintf(stderr, "usage: broker --policy path|fd|sealed [--allowlist file] [--timeout-ms N]\n"); return 2; }
    }
    if (!policy || (strcmp(policy, "path") && strcmp(policy, "fd") && strcmp(policy, "sealed"))) {
        fprintf(stderr, "broker: --policy must be path, fd or sealed\n"); return 2;
    }
    if (load_allowlist(allowfile) <= 0) { fprintf(stderr, "broker: allowlist is empty\n"); return 2; }
    const char *g = getenv("RP_GAP_US"); if (g) gap_us = atol(g);
    signal(SIGPIPE, SIG_IGN);

    char line[8192];
    while (fgets(line, sizeof line, stdin)) {
        char *s = line; while (*s == ' ' || *s == '\t') s++;
        size_t L = strlen(s); while (L && (s[L-1] == '\n' || s[L-1] == '\r')) s[--L] = 0;
        if (!L || *s == '#') continue;
        if (strncmp(s, "RUN ", 4) != 0) { fprintf(stderr, "broker: unknown request: %s\n", s); continue; }
        char *args[64]; int n = 0;
        for (char *tok = strtok(s + 4, " \t"); tok && n < 63; tok = strtok(NULL, " \t")) args[n++] = tok;
        args[n] = NULL;
        if (n == 0) continue;
        run_one(policy, args, timeout_ms);
    }
    return 0;
}
