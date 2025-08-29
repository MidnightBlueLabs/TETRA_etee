#include <inttypes.h>
#include <assert.h>
#include <stdio.h>

char hexdump_buf[1024];
char *hexdump(const uint8_t *buf, uint32_t len) {
    assert(2 * len + 1 < sizeof(hexdump_buf));
    for (uint32_t i = 0; i < len; i++) {
        sprintf(hexdump_buf + 2 * i, "%02x", buf[i]);
    }
    return hexdump_buf;
}

char *bindump(const uint8_t *buf, uint32_t len_bits) {
    assert(len_bits + 1 < sizeof(hexdump_buf));
    for (uint32_t i = 0; i < len_bits; i++) {
        sprintf(hexdump_buf + i, "%d", (buf[i/8] & (0x80 >> (i % 8))) > 0);
    }
    return hexdump_buf;
}

void xor_bytes(uint8_t *lpInOut, const uint8_t *lpIn2, uint32_t dwNumBytes) {
    for (uint32_t i = 0; i < dwNumBytes; i++) {
        lpInOut[i] ^= lpIn2[i];
    }
}

void xor_bits(uint8_t *lpOut, const uint8_t *lpXorWithOut, uint32_t dwNumBits) {
    
    int dwNumBytes = dwNumBits / 8;
    dwNumBits = dwNumBits % 8;
    xor_bytes(lpOut, lpXorWithOut, dwNumBytes);

    // Last byte is xorred only partially:
    if (dwNumBits) {
        uint8_t bLastXorByte = lpXorWithOut[dwNumBytes];
        bLastXorByte &= 0xFF << (8-dwNumBits);
        lpOut[dwNumBytes] ^= bLastXorByte;
    }
}