#pragma once

#include <inttypes.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

char *hexdump(const uint8_t *buf, uint32_t len);
char *bindump(const uint8_t *buf, uint32_t len_bits);
void xor_bytes(uint8_t *lpInOut, const uint8_t *lpIn2, uint32_t dwNumBytes);
void xor_bits(uint8_t *lpOut, const uint8_t *lpXorWithOut, uint32_t dwNumBits);
