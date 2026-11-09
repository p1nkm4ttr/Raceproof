/* RaceProof fixture. Freestanding (no libc) so the smallest build is a few KiB
 * and file size is controlled only by PAD_BYTES.
 *
 * Prints "RACEPROOF_ID=<PROG_ID> PID=<pid>\n" to stdout, then a second line
 * "RACEPROOF_PAD=<fnv1a-64 of the padding, hex>\n", and exits 0.
 * The ID line goes out first so launch latency (time to first byte) does not
 * include the pad hash. Together the two lines attest the two regions the
 * experiment's attacks target: the code that prints the ID, and the padding.
 * They do not attest the ELF header or any other byte; this is a ground truth
 * for the chosen A/B attacks, not a general integrity check.
 * Build: gcc -O2 -static -nostdlib -nostartfiles -fno-stack-protector \
 *        -DPROG_ID='A' -DPAD_BYTES=1048576 -o prog_a_1m prog.c
 * x86-64 Linux only (raw syscalls). */

#ifndef PROG_ID
#error "define PROG_ID as a char literal, e.g. -DPROG_ID='A'"
#endif
#ifndef PAD_BYTES
#define PAD_BYTES 0
#endif

static long sys3(long n, long a, long b, long c) {
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return ret;
}
#define SYS_write 1
#define SYS_getpid 39
#define SYS_exit 60

/* Padding lives in .rodata and is filled entirely with PROG_ID, so prog_a and prog_b
 * differ at every padding byte. A torn copy (part A, part B) is then detectable at any
 * offset; with a zero-filled pad, a mid-copy write of B's tail would be byte-identical
 * to A's and tearing there would be invisible. The first byte is read so the array
 * cannot be dropped by the optimiser. */
#if PAD_BYTES > 0
static const unsigned char pad[PAD_BYTES] = { [0 ... PAD_BYTES - 1] = PROG_ID };
#endif

void _start(void) {
    char buf[64];
    int i = 0;
    const char *p = "RACEPROOF_ID=";
    while (*p) buf[i++] = *p++;
    buf[i++] = PROG_ID;
    p = " PID=";
    while (*p) buf[i++] = *p++;
    long pid = sys3(SYS_getpid, 0, 0, 0);
    char num[20]; int k = 0;
    if (pid == 0) num[k++] = '0';
    while (pid > 0) { num[k++] = '0' + (pid % 10); pid /= 10; }
    while (k > 0) buf[i++] = num[--k];
    buf[i++] = '\n';
    sys3(SYS_write, 1, (long)buf, i);

    /* Second line: FNV-1a 64 over the padding (0 bytes if unpadded). */
    unsigned long long h = 1469598103934665603ULL;
#if PAD_BYTES > 0
    for (long j = 0; j < PAD_BYTES; j++) { h ^= pad[j]; h *= 1099511628211ULL; }
#endif
    i = 0;
    p = "RACEPROOF_PAD=";
    while (*p) buf[i++] = *p++;
    for (int s = 60; s >= 0; s -= 4) buf[i++] = "0123456789abcdef"[(h >> s) & 15];
    buf[i++] = '\n';
    sys3(SYS_write, 1, (long)buf, i);
    sys3(SYS_exit, 0, 0, 0);
    for (;;) {}
}
