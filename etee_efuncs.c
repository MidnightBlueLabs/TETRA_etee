#include <stdint.h>

#include "etee_efuncs_aes.h"


void etee_e1(const uint8_t *lpKey, uint8_t *lpIvInOut, uint8_t *lpKsOut, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        etee_e1_aes(lpKey, lpIvInOut, lpKsOut, eAlgId);
    }
}

void etee_e2(const uint8_t *lpKey, const uint8_t *lpCtIn, uint8_t *lpPtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        etee_e2_aes(lpKey, lpCtIn, lpPtOut, dwNumBlocks, eAlgId);
    }
}
void etee_e2_inv(const uint8_t *lpKey, const uint8_t *lpPtIn, uint8_t *lpCtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        etee_e2inv_aes(lpKey, lpPtIn, lpCtOut, dwNumBlocks, eAlgId);
    }
}

void etee_e3(const uint8_t *lpKey, uint8_t *lpInOut, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        etee_e3_aes(lpKey, lpInOut, eAlgId);        
    }
}

void etee_e4(const uint8_t *lpKey, const uint8_t *lpIvIn, uint8_t *lpInOut, uint32_t dwNumBlocks, uint8_t bEncrypt, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        etee_e4_aes(lpKey, lpIvIn, lpInOut, dwNumBlocks, bEncrypt, eAlgId);
    }
}

void etee_e5(const uint8_t *lpKey, const uint8_t *lpIv, uint8_t *lpKs_out, enum tetra_etee_algid eAlgId, uint32_t dwNumBlocks, uint8_t *lpNextPiv_out) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        etee_e5_aes(lpKey, lpIv, lpKs_out, eAlgId, dwNumBlocks, lpNextPiv_out);        
    }
}

void etee_e6(const uint8_t *lpKey, const uint8_t *lpIn, uint32_t dwNumBlocks, uint8_t *lpMac1, uint8_t *lpMac2, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        etee_e6_aes(lpKey, lpIn, dwNumBlocks, lpMac1, lpMac2, eAlgId);        
    }
}

void etee_crypt_blk(const uint8_t *lpIn, const uint8_t *lpKey, uint8_t *lpOut, int32_t bEncrypt, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_IDEA) {
        return;
    } else {
        aes_enc_or_dec_blk(lpIn, lpKey, lpOut, bEncrypt, eAlgId);        
    }
}

void etee_process_key(uint8_t *lpKeyInOut, enum tetra_etee_algid eAlgId) {
    if (eAlgId == ETEE_ALG_AES56) {
        etee_process_key_aes56(lpKeyInOut);
    }
}
