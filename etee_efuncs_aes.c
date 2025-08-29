#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <openssl/aes.h>

#include "etee.h"
#include "common.h"

void etee_e1_aes(const uint8_t *lpAesKey, uint8_t *lpIvInOut, uint8_t *lpKsOut, enum tetra_etee_algid eAlgId) {

    AES_KEY stAesKey;
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);
    
    uint8_t abAesState[16];
    AES_set_encrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);

    memcpy(abAesState, lpIvInOut, 8);
    memcpy(&abAesState[8], lpIvInOut, 8);
    
    AES_encrypt(abAesState, abAesState, &stAesKey);
    memcpy(lpKsOut, abAesState, 16);
    AES_encrypt(abAesState, abAesState, &stAesKey);
    memcpy(&lpKsOut[16], abAesState, 16);
    AES_encrypt(abAesState, abAesState, &stAesKey);
    memcpy(&lpKsOut[32], abAesState, 3);
    lpKsOut[35] &= 0xc0; // Mask out last 6 bits
    
    // Use 8 of the remaining ks bytes to use for next IV
    memcpy(lpIvInOut, &abAesState[8], 8);
}

void etee_e2_aes(const uint8_t *lpAesKey, const uint8_t *lpCtIn, uint8_t *lpPtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId) {

    uint8_t abBuf[16];
    AES_KEY stAesKey;
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);
    if (lpstEteeAlg == 0) {
        return;
    }
    
    AES_set_decrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
    
    for (uint32_t i = 0; i < dwNumBlocks; i++) {
        memcpy(abBuf, &lpCtIn[16*i], 16);
        AES_decrypt(abBuf, abBuf, &stAesKey);
        if (i > 0) {
            xor_bytes(abBuf, &lpCtIn[16 * (i-1)], 16);
        }
        memcpy(&lpPtOut[16*i], abBuf, 16);        
    }
}

void etee_e2inv_aes(const uint8_t *lpAesKey, const uint8_t *lpPtIn, uint8_t *lpCtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId) {

    uint8_t abBuf[16];
    AES_KEY stAesKey;
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);
    if (lpstEteeAlg == 0) {
        return;
    }
    
    AES_set_encrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);

    for (uint32_t i = 0; i < dwNumBlocks; i++) {
        memcpy(abBuf, &lpPtIn[16*i], 16);
        
        if (i > 0) {
            xor_bytes(abBuf, &lpCtOut[16 * (i-1)], 16);
        }
        AES_encrypt(abBuf, abBuf, &stAesKey);
        memcpy(&lpCtOut[16*i], abBuf, 16);        
    }
}

void etee_e3_aes(const uint8_t *lpAesKey, uint8_t *lpInOut, enum tetra_etee_algid eAlgId) {

    AES_KEY stAesKey;
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);

    AES_set_encrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
    AES_encrypt(lpInOut, lpInOut, &stAesKey);
}

void etee_e4_aes(const uint8_t *lpAesKey, const uint8_t *lpIvIn, uint8_t *lpInOut, uint32_t dwNumBlocks, uint8_t bEncrypt, enum tetra_etee_algid eAlgId) {

    AES_KEY stAesKey;
    uint32_t i;

    if (dwNumBlocks == 0) {
        return;
    }
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);
    if (lpstEteeAlg == 0) {
        return;
    }
    
    if (bEncrypt == 0) {
        AES_set_decrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
        dwNumBlocks--;
        while (dwNumBlocks != 0) {
            AES_decrypt(&lpInOut[16 * dwNumBlocks], &lpInOut[16 * dwNumBlocks], &stAesKey);
            xor_bytes(&lpInOut[16 * dwNumBlocks], &lpInOut[16 * (dwNumBlocks-1)], 16);
            dwNumBlocks--;
        }
        AES_decrypt(lpInOut, lpInOut, &stAesKey);
        xor_bytes(lpInOut, lpIvIn, 16);
    } else {
        xor_bytes(lpInOut, lpIvIn, 16);
        AES_set_encrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
        AES_encrypt(lpInOut, lpInOut, &stAesKey);
        if (dwNumBlocks <= 1) {
            return;
        }
        for(i = 1, dwNumBlocks--; dwNumBlocks != 0; dwNumBlocks--, i++) {
            xor_bytes(&lpInOut[i*16], &lpInOut[(i-1)*16], 16);
            AES_encrypt(&lpInOut[i*16], &lpInOut[i*16], &stAesKey);
        }
    }
}

void etee_e5_aes(const uint8_t *lpAesKey, const uint8_t *lpIv, uint8_t *lpKs_out, enum tetra_etee_algid eAlgId, uint32_t dwNumBlocks, uint8_t *lpNextPiv_out) {

    AES_KEY stAesKey;
    uint8_t abKsBlock[16];
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);

    AES_set_encrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
    memcpy(abKsBlock, lpIv, 16);

    // Generate keystream blocks
    for (uint32_t i = 0; i < dwNumBlocks; i++) {
        AES_encrypt(abKsBlock, abKsBlock, &stAesKey);
        memcpy(&lpKs_out[16*i], abKsBlock, 16);
    }
    
    AES_encrypt(abKsBlock, abKsBlock, &stAesKey);
    memcpy(lpNextPiv_out, abKsBlock, 9);
}

void etee_e6_aes(const uint8_t *lpAesKey, const uint8_t *lpIn, uint32_t dwNumBlocks, uint8_t *lpMac1, uint8_t *lpMac2, enum tetra_etee_algid eAlgId) {
    
    AES_KEY stAesKey;
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);
    uint8_t abBuf[16];

    AES_set_encrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
    memcpy(abBuf, lpIn, lpstEteeAlg->bBlockSize);

    AES_encrypt(abBuf, abBuf, &stAesKey);

    // Tell compiler block size can't be over 16
    assert(lpstEteeAlg->bBlockSize == 16);
    
    for (uint32_t i = 1; i < dwNumBlocks; i++) {
        xor_bytes(abBuf, &lpIn[i * lpstEteeAlg->bBlockSize], lpstEteeAlg->bBlockSize);
        AES_encrypt(abBuf, abBuf, &stAesKey);
    }

    memcpy(lpMac1, abBuf, 4);
    memcpy(lpMac2, &abBuf[12], 4);
}

void aes_enc_or_dec_blk(const uint8_t *lpIn, const uint8_t *lpAesKey, uint8_t *lpOut, int32_t bEncrypt, enum tetra_etee_algid eAlgId) {

    AES_KEY stAesKey;
    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);

    if (lpstEteeAlg == 0) {
        return;
    }

    // Tell compiler block size can't be over 16
    assert(lpstEteeAlg->bBlockSize == 16);

    memcpy(lpOut, lpIn, lpstEteeAlg->bBlockSize);
    if (bEncrypt) {
        AES_set_encrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
        AES_encrypt(lpOut, lpOut, &stAesKey);
    } else {
        AES_set_decrypt_key(lpAesKey, lpstEteeAlg->bKeySize * 8, &stAesKey);
        AES_decrypt(lpOut, lpOut, &stAesKey);
    }
}

void etee_process_key_aes56(uint8_t *lpKey_InOut) {
    lpKey_InOut[0] = lpKey_InOut[0xE];
    lpKey_InOut[1] = lpKey_InOut[0xF];
    for (int i = 0; i < 7; i++) {
        lpKey_InOut[i + 2] = lpKey_InOut[i + 9];
    }
}
