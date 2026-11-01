#ifndef RP_POLICY_H
#define RP_POLICY_H
#include <stdint.h>

/* Status the broker child reports to the parent through a pipe. It is sent once
 * after the decision (before exec) and again if exec returns with an error. */
struct status {
    int decision;            /* 0 = APPROVE, 1 = REJECT */
    int exec_errno;          /* 0 unless exec returned */
    int seal_ok;             /* sealed policy: F_GET_SEALS matched what we set */
    int torn;                /* sealed policy: copy neither all-A nor all-B */
    long torn_first;         /* first and last differing offsets, -1 if not torn */
    long torn_last;
    long t_check_us;         /* hashing time */
    long t_copy_us;          /* copy + seal time (sealed only) */
    long bytes_hashed;
    long bytes_copied;
    char observed_hex[65];
};

/* Shared helpers implemented in broker.c */
long now_us(void);
int allowlist_has(const char *hex);
int hash_fd(int fd, char hex[65], long *bytes);   /* pread from offset 0 to EOF */
int elf_magic_ok(int fd);
void send_status(const struct status *st);
void apply_gap(void);                              /* RP_GAP_US sleep between hash and exec */
extern char **environ;

/* Policies. Each runs in the forked child. On approval it execs and never returns;
 * on rejection it exits 3; if exec fails it reports errno and exits 127. */
void policy_path(const char *path, char **argv);
void policy_fd(const char *path, char **argv);
void policy_sealed(const char *path, char **argv);

#endif
