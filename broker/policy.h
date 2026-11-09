#ifndef RP_POLICY_H
#define RP_POLICY_H
#include <stdint.h>

/* Status the broker child reports to the parent through a pipe. It is sent once
 * after the decision (before exec) and again if exec returns with an error. */
struct status {
    int decision;            /* 0 = APPROVE, 1 = REJECT (content failed validation), 2 = ERROR (the broker itself failed:
                                open, read, memfd_create, seal). An ERROR is never a policy outcome. */
    int exec_errno;          /* errno of the failing call: exec, or the broker failure behind an ERROR */
    int seal_ok;             /* sealed policy: F_GET_SEALS matched what we set */
    int torn_checked;        /* sealed policy: 1 if the copy was compared with both references */
    int torn;                /* sealed policy: copy matches neither reference (only meaningful if torn_checked) */
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
extern const char *hash_impl;                    /* "vendored-c" or "openssl-evp" */
int elf_magic_ok(int fd);
void send_status(const struct status *st);
void apply_gap(void);                              /* RP_GAP_US sleep between hash and exec */
extern char **environ;

/* Policies. Each runs in the forked child. On approval it execs and never returns;
 * on rejection it exits 3; on a broker-side error it exits 4; if exec fails it
 * reports errno and exits 127. */
#define RP_APPROVE 0
#define RP_REJECT  1
#define RP_ERROR   2
#define EXIT_REJECT 3
#define EXIT_ERROR  4
void policy_path(const char *path, char **argv);
void policy_fd(const char *path, char **argv);
void policy_sealed(const char *path, char **argv);

#endif
