#ifndef RP_SHA256_H
#define RP_SHA256_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    size_t buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t n);
void sha256_final(sha256_ctx *c, unsigned char out[32]);
/* Hex-encode a 32-byte digest into hex[65] (NUL-terminated). */
void sha256_hex(const unsigned char d[32], char hex[65]);

#endif
