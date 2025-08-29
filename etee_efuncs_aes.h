#pragma once

#include <stdbool.h>
#include <inttypes.h>

#include "etee.h"

void etee_e1_aes(const uint8_t *lpAesKey, uint8_t *lpIvInOut, uint8_t *lpKsOut, enum tetra_etee_algid eAlgId);
void etee_e2_aes(const uint8_t *lpAesKey, const uint8_t *lpCtIn, uint8_t *lpPtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId);
void etee_e2inv_aes(const uint8_t *lpAesKey, const uint8_t *lpPtIn, uint8_t *lpCtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId);
void etee_e3_aes(const uint8_t *lpAesKey, uint8_t *lpInOut, enum tetra_etee_algid eAlgId);
void etee_e4_aes(const uint8_t *lpAesKey, const uint8_t *lpIvIn, uint8_t *lpInOut, uint32_t dwNumBlocks, uint8_t bEncrypt, enum tetra_etee_algid eAlgId);
void etee_e5_aes(const uint8_t *lpAesKey, const uint8_t *lpIv, uint8_t *lpKs_out, enum tetra_etee_algid eAlgId, uint32_t dwNumBlocks, uint8_t *lpNextPiv_out);
void etee_e6_aes(const uint8_t *lpAesKey, const uint8_t *lpIn, uint32_t dwNumBlocks, uint8_t *lpMac1, uint8_t *lpMac2, enum tetra_etee_algid eAlgId);
void aes_enc_or_dec_blk(const uint8_t *lpIn, const uint8_t *lpAesKey, uint8_t *lpOut, int32_t bEncrypt, enum tetra_etee_algid eAlgId);
void etee_process_key_aes56(uint8_t *lpKey_InOut);
