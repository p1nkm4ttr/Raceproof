#define _GNU_SOURCE
#include "barrier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int to_fd = -1, from_fd = -1, checked = 0, enabled = 0;

static void die(const char *what) {
    fprintf(stderr, "broker: barrier %s: %s\n", what, strerror(errno));
    _exit(120);
}

static void open_fifos(void) {
    const char *dir = getenv("RP_BARRIER_DIR");
    checked = 1;
    if (!dir || !*dir) return;
    char p[4096];
    snprintf(p, sizeof p, "%s/to_updater", dir);
    to_fd = open(p, O_WRONLY | O_CLOEXEC);          /* blocks until the updater opens for read */
    if (to_fd < 0) die("open to_updater");
    snprintf(p, sizeof p, "%s/from_updater", dir);
    from_fd = open(p, O_RDONLY | O_CLOEXEC);
    if (from_fd < 0) die("open from_updater");
    enabled = 1;
}

void barrier_stage(const char *stage) {
    if (!checked) open_fifos();
    if (!enabled) return;
    char line[64];
    int n = snprintf(line, sizeof line, "%s\n", stage);
    if (write(to_fd, line, n) != n) die("write stage");
    char buf[8]; int got = 0;
    while (got < 3) {                                /* wait for "go\n" */
        ssize_t r = read(from_fd, buf + got, 3 - got);
        if (r <= 0) die("read go");
        got += r;
    }
}
