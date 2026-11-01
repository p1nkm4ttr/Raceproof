/* Sealed-copy policy. Implemented in session S5; stub so the broker links. */
#define _GNU_SOURCE
#include "policy.h"
#include <stdio.h>
#include <unistd.h>

void policy_sealed(const char *path, char **argv) {
    (void)path; (void)argv;
    fprintf(stderr, "broker: sealed policy not implemented yet\n");
    _exit(121);
}
