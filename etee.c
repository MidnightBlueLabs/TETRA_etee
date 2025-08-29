
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

#include "common.h"
#include "etee.h"
#include "etee_efuncs.h"

const EteeAlg g_astEteeAlgs[4] = {
    {.eAlgId = ETEE_ALG_AES56,  .szAlgName = "AES56",  .bKeySize = 16, .bBlockSize = 16},
    {.eAlgId = ETEE_ALG_AES128, .szAlgName = "AES128", .bKeySize = 16, .bBlockSize = 16},
    {.eAlgId = ETEE_ALG_AES256, .szAlgName = "AES256", .bKeySize = 32, .bBlockSize = 16},
    {.eAlgId = ETEE_ALG_IDEA,   .szAlgName = "IDEA",   .bKeySize = 16, .bBlockSize = 8}
};

static const uint8_t g_abSdsKeyProcessingIv[32] = {
    0xAE, 0x1C, 0xAB, 0xD9, 0xBD, 0xFF, 0xD6, 0xD5, 0x4E, 0x55, 0xC5, 0xCD, 0x1C, 0xFA, 0x92, 0xDC, 
    0x8B, 0x73, 0x8D, 0x72, 0x78, 0x9F, 0x75, 0x70, 0x17, 0xB6, 0xE6, 0xAD, 0x62, 0x44, 0xF8, 0x8A
};

static const uint8_t g_abSdsKeyPreprocessingIv[32] = {
    0x9D, 0xFF, 0x47, 0x3D, 0x07, 0x23, 0x52, 0xE4, 0xE5, 0x6C, 0x18, 0x7E, 0x20, 0x58, 0x8F, 0xB3, 
    0xA0, 0x52, 0xB9, 0xAF, 0x4D, 0xB5, 0x0A, 0x3B, 0x80, 0x08, 0xAC, 0x98, 0x03, 0x15, 0xC6, 0xEA
};

const EteeAlg *get_alg_properties(enum tetra_etee_algid eAlgId) {
    
    for (int i = 0; i < 4; i++) {
        if (g_astEteeAlgs[i].eAlgId == eAlgId) {
            return &g_astEteeAlgs[i];
        }
    }
    return NULL;
}

static uint32_t get_field(const uint8_t *lpBuf, uint32_t dwFieldNo) {
    assert(0 < dwFieldNo && dwFieldNo <= 4);
    uint32_t dwRet = 0;
    for (uint32_t i = 0; i < dwFieldNo; i++) {
        dwRet <<= 8;
        dwRet |= lpBuf[i];
    }
    return dwRet;
}

static uint32_t calc_num_blocks(const EteeAlg *lpKekAlg, const EteeAlg *lpKeyAlg) {
    uint32_t dwPayloadSize = lpKeyAlg->bKeySize + 12;
    uint32_t dwRemainder = dwPayloadSize % lpKekAlg->bBlockSize;
    if (dwRemainder) {
        dwPayloadSize = lpKekAlg->bBlockSize - dwRemainder + dwPayloadSize;
    }
    return dwPayloadSize / lpKekAlg->bBlockSize;
}

static void ReAlignCCSUMfromE3toTxSF(uint8_t *lpChecksumIn, uint8_t *lpOut, bool bIsIdea) {
    // For AES based algos, use lpOut[13:16], for IDEA, use lpOut[5:8]
    uint8_t *lpInput = &lpChecksumIn[bIsIdea ? 5 : 13];
    lpOut[0] = (lpInput[0] >> 4) & 3;
    lpOut[1] = (lpInput[1] >> 4) | (lpInput[0] << 4);
    lpOut[2] = (lpInput[2] >> 4) | (lpInput[1] << 4);
    lpOut[3] =                     (lpInput[2] << 4);
}


static void GenerateKT(uint8_t *lpOutput, uint32_t dwKeyId, uint16_t eAlgId, uint32_t wPadWord) {
    lpOutput[0] = wPadWord >> 8;
    lpOutput[1] = wPadWord;
    lpOutput[2] = dwKeyId >> 12;
    lpOutput[3] = dwKeyId >> 4;
    lpOutput[4] = (dwKeyId << 4) | (eAlgId >> 6);
    lpOutput[5] = eAlgId << 2;
    lpOutput[6] = ~wPadWord >> 8;
    lpOutput[7] = ~wPadWord;
}

static void generate_accsum(uint8_t *lpOut, const uint8_t *lpKey, uint8_t bIn0, int32_t dwNonce, const uint8_t *lpMac1, int32_t dwAlgId) {
    
    const EteeAlg *lpstAlg = get_alg_properties(dwAlgId);
    
    uint8_t abBuf[lpstAlg->bBlockSize];
    abBuf[0] = bIn0;
    abBuf[1] = dwNonce >> 16;
    abBuf[2] = dwNonce >> 8;
    abBuf[3] = dwNonce & 0xFF;
    memcpy(&abBuf[4], lpMac1, 4);

    if (lpstAlg->bBlockSize >= 16) {
        int32_t dwNumExtraBlocks = (lpstAlg->bBlockSize / 8) - 1;
        for (int i = 0; i < dwNumExtraBlocks; i++) {
            memcpy(&abBuf[8+8*i], abBuf, 8);
        }
    }

    uint8_t abCtOut[16];
    etee_crypt_blk(abBuf, lpKey, abCtOut, 1, lpstAlg->eAlgId);
    memcpy(lpOut, abCtOut, 4);
}

static void pad_end_of_ccsum_fields(uint8_t *lpBuf_InOut, int dwUsedBits, int dwBufLen) {
    
    int dwByteOff = dwUsedBits / 8;
    int dwBitOff = dwUsedBits % 8;
    assert(dwByteOff < dwBufLen);
    
    lpBuf_InOut[dwByteOff] |= (0x80 >> dwBitOff);
    lpBuf_InOut[dwByteOff] &= ~(0xFF >> (dwBitOff + 1));

    for (int i = dwByteOff + 1; i < dwBufLen; i++) {
        lpBuf_InOut[i] = 0;
    }
}

static void assemble_iv(uint8_t *lpIvOut, uint8_t bSvType, const uint8_t *lpSdsPiv, const uint8_t *lpMac1, const uint8_t *lpOptionalIssi, int32_t dwAlgBlockSize) {

    assert(bSvType == 2 || dwAlgBlockSize == 16);

    if (bSvType == 0 || bSvType == 1) {
        
        memcpy(lpIvOut, lpSdsPiv, 9);
        memcpy(&lpIvOut[9], lpMac1, 4);
        
        if (bSvType == 0) {
            memset(&lpIvOut[13], 0, 3);
        } else {
            memcpy(&lpIvOut[13], lpOptionalIssi, 3);
        }
        
    } else { // bSvType == 2

        memcpy(lpIvOut, lpSdsPiv, 4);
        memcpy(&lpIvOut[4], lpMac1, 4);

        if (dwAlgBlockSize == 16) {
            memcpy(&lpIvOut[8], lpIvOut, 8);
        }
    }
}

static void derive_mac_key(uint8_t *lpKeyOut, const uint8_t *lpKeyIn, const EteeAlg *lpstEteeAlg) {

    uint32_t dwBlockSize = lpstEteeAlg->bBlockSize;
    uint32_t dwAlgKeySize = lpstEteeAlg->bKeySize;
    assert(dwBlockSize && dwAlgKeySize && (dwAlgKeySize % dwBlockSize == 0));

    int32_t dwNumBlocks = dwAlgKeySize / dwBlockSize;
    assert(dwNumBlocks);

    uint8_t abBuf[16];
    uint32_t dwBlocksDone = 0;
    while (dwNumBlocks) {

        memcpy(abBuf, &g_abSdsKeyPreprocessingIv[dwBlocksDone * dwBlockSize], dwBlockSize);
        if (dwBlocksDone > 0) {
            xor_bytes(abBuf, &lpKeyOut[(dwBlocksDone - 1) * dwBlockSize], dwBlockSize);
        }
        etee_crypt_blk(abBuf, lpKeyIn, &lpKeyOut[dwBlocksDone * dwBlockSize], 1, lpstEteeAlg->eAlgId);

        dwNumBlocks--;
        dwBlocksDone++;
    }
}

void etee_generate_syncframe(const EteeKey *lpstTek, const uint8_t *lpIv, uint8_t *lpOut) {

    const EteeAlg *lpstEteeAlg = get_alg_properties(lpstTek->eAlgId);

    uint8_t abMacData[16];
    uint8_t abCcsum[4];

    GenerateKT(abMacData, lpstTek->dwKeyId, lpstTek->eAlgId, 0);
    memcpy(&abMacData[8], lpIv, 8);

    etee_e3(lpstTek->abKey, abMacData, lpstTek->eAlgId);
    ReAlignCCSUMfromE3toTxSF(abMacData, abCcsum, lpstEteeAlg->eAlgId == ETEE_ALG_IDEA);

    lpOut[0] = ((lpstTek->eAlgId >> 8) & 3) | 0x10;
    lpOut[1] = lpstTek->eAlgId;    
    memcpy(&lpOut[2], lpIv, 8);
    lpOut[10] = (lpstTek->dwKeyId >> 14) & 0x3f;
    lpOut[11] = lpstTek->dwKeyId >> 6;
    lpOut[12] = lpstTek->dwKeyId << 2;
    lpOut[12] |= abCcsum[0];
    lpOut[13] = abCcsum[1];
    lpOut[14] = abCcsum[2];
    lpOut[15] = abCcsum[3];
}

const EteeKey *etee_unpack_syncframe(const EteeKey *lpstKeys, uint32_t dwNumKeys, const uint8_t *lpFrameIn, uint8_t *lpIvOut) {

    uint8_t abCcsumRecvd[4], abCcsumComputed[4];
    uint16_t eAlgId = ((lpFrameIn[0] << 8) | lpFrameIn[1]) & 0x3FF;
    memcpy(lpIvOut, &lpFrameIn[2], 8);
    uint32_t dwKeyId = (((lpFrameIn[10] << 16) | (lpFrameIn[11] << 8) | lpFrameIn[12]) >> 2) & 0xFFFFF;
    memcpy(abCcsumRecvd, &lpFrameIn[12], 4);
    abCcsumRecvd[0] &= 3;

    const EteeAlg *lpstEteeAlg = get_alg_properties(eAlgId);
    if (!lpstEteeAlg) {
        return NULL;
    }

    const EteeKey *lpstKey = 0;
    for (uint32_t i = 0; i < dwNumKeys; i++) {
        if (lpstKeys[i].eAlgId == eAlgId && lpstKeys[i].dwKeyId == dwKeyId) {
            lpstKey = &lpstKeys[i];
            break;
        }
    }
    if (!lpstKey) {
        return NULL;
    }

    uint8_t abMacData[16]; 
    GenerateKT(abMacData, dwKeyId, eAlgId, 0);
    memcpy(&abMacData[8], lpIvOut, 8);

    etee_e3(lpstKey->abKey, abMacData, eAlgId);
    ReAlignCCSUMfromE3toTxSF(abMacData, abCcsumComputed, lpstEteeAlg->eAlgId == ETEE_ALG_IDEA);
    if (memcmp(abCcsumComputed, abCcsumRecvd, 4)) {
        // checksum mismatch, return null;
        return NULL;
    }
    // Checksum ok, return corresponding key
    return lpstKey;
}

bool etee_seal_tek(EteeKey *lpKek, EteeKey *lpTek, uint8_t *lpSealedOut) {
    const EteeAlg *lpKekAlg = get_alg_properties(lpKek->eAlgId);
    const EteeAlg *lpTekAlg = get_alg_properties(lpTek->eAlgId);
    if (!lpKekAlg || !lpTekAlg) {
        return false;
    }
    
    uint32_t dwNumBlocks = calc_num_blocks(lpKekAlg, lpTekAlg);
    uint8_t abUnsealed[lpTekAlg->bKeySize + 4];

    memset(abUnsealed, 0, dwNumBlocks * lpKekAlg->bBlockSize);
    memcpy(abUnsealed, lpTek->abKey, lpTekAlg->bKeySize);
    memset(lpSealedOut, 0, dwNumBlocks * lpKekAlg->bBlockSize);
    
    // 20-bit TekId
    abUnsealed[lpTekAlg->bKeySize] = lpTek->dwKeyId >> 12;
    abUnsealed[lpTekAlg->bKeySize + 1] = lpTek->dwKeyId >> 4;
    abUnsealed[lpTekAlg->bKeySize + 2] = lpTek->dwKeyId << 4;
    // 10-bit AlgId
    abUnsealed[lpTekAlg->bKeySize + 2] |= (lpTekAlg->eAlgId >> 6);
    abUnsealed[lpTekAlg->bKeySize + 3] = lpTekAlg->eAlgId << 2;
    
    etee_e2_inv(lpKek->abKey, abUnsealed, lpSealedOut, dwNumBlocks, lpKek->eAlgId);
    return true;
}

bool etee_unseal_tek(EteeKey *lpKek, EteeKey *lpTekInOut, uint8_t *lpSealedIn, uint8_t *lpUnsealedOut) {

    const EteeAlg *lpKekAlg = get_alg_properties(lpKek->eAlgId);
    const EteeAlg *lpTekAlg = get_alg_properties(lpTekInOut->eAlgId);
    if (!lpKekAlg || !lpTekAlg) {
        return false;
    }

    uint32_t dwNumBlocks = calc_num_blocks(lpKekAlg, lpTekAlg);
    etee_e2(lpKek->abKey, lpSealedIn, lpUnsealedOut, dwNumBlocks, lpKek->eAlgId);
    memcpy(lpTekInOut->abKey, lpUnsealedOut, lpTekAlg->bKeySize);
    etee_process_key(lpTekInOut->abKey, lpTekAlg->eAlgId);
    
    uint32_t dwDecryptedKeyId = get_field(&lpUnsealedOut[lpTekAlg->bKeySize], 3);
    dwDecryptedKeyId = dwDecryptedKeyId >> 4 & 0xFFFFF;
    uint32_t dwDecryptedAlgId = get_field(&lpUnsealedOut[lpTekAlg->bKeySize + 2], 2);
    dwDecryptedAlgId = (dwDecryptedAlgId >> 2) & 0x3FF;

    if (lpTekInOut->eAlgId != dwDecryptedAlgId || lpTekInOut->dwKeyId != dwDecryptedKeyId) {
        return false;
    }

    return true;
}

bool etee_kmm_req(EteeKeystore *lpstKeystore, EteeKmmReq *lpCtx) {

    const EteeKey *lpstSealKey = 0;    
    if (lpCtx->wKekAlgId == lpstKeystore->stSek.eAlgId && lpCtx->dwKekId == lpstKeystore->stSek.dwKeyId) {
        lpstSealKey = &lpstKeystore->stSek;
    } 
    if (lpCtx->wKekAlgId == lpstKeystore->stKek.eAlgId && lpCtx->dwKekId == lpstKeystore->stKek.dwKeyId) {
        lpstSealKey = &lpstKeystore->stKek;
    } 
    if (!lpstSealKey) {
        return false;
    }
    
    const EteeAlg *lpstSealAlg = get_alg_properties(lpstSealKey->eAlgId);
    if (lpCtx->dwBufLen == 0 || lpCtx->dwBufLen > 160 || (lpCtx->dwBufLen % lpstSealAlg->bBlockSize) > 0) {
        return false;
    }
    
    uint32_t dwNumBlocks = lpCtx->dwBufLen / lpstSealAlg->bBlockSize;
    uint8_t abBuf[lpCtx->dwBufLen];
    if (lpCtx->bEncrypt) {
        memcpy(abBuf, lpCtx->abPtBuf, lpCtx->dwBufLen);
        etee_e4(lpstSealKey->abKey, lpCtx->abIv, abBuf, dwNumBlocks, 1, lpstSealKey->eAlgId);
        memcpy(lpCtx->abCtBuf, abBuf, lpCtx->dwBufLen);
    } else {
        memcpy(abBuf, lpCtx->abCtBuf, lpCtx->dwBufLen);
        etee_e4(lpstSealKey->abKey, lpCtx->abIv, abBuf, dwNumBlocks, 0, lpstSealKey->eAlgId);
        memcpy(lpCtx->abPtBuf, abBuf, lpCtx->dwBufLen);
    }
    return true;
}

bool etee_sds_encrypt(uint8_t *lpPackedOut, EteeSdsCtx *lpCtx) {

    const EteeKey *lpstKey = lpCtx->lpstKey;
    const EteeAlg *lpstAlg = get_alg_properties(lpstKey->eAlgId);

    if(lpCtx->bSvType > 2 || !lpstAlg) {
        return false;
    }

    uint8_t abMacDataBuf[256];
    uint32_t dwMacDataHdrLen;
    uint32_t dwPtLenBytes = (lpCtx->dwPtLenBits + 7) / 8;
    uint32_t dwPivLen = (lpCtx->bSvType == 2 ? 4 : 9);

    uint8_t abXorredTek[lpstAlg->bKeySize];
    uint8_t abMacKey[lpstAlg->bKeySize];
    memcpy(abXorredTek, lpstKey->abKey, lpstAlg->bKeySize);
    xor_bytes(abXorredTek, g_abSdsKeyProcessingIv, lpstAlg->bKeySize);
    derive_mac_key(abMacKey, abXorredTek, lpstAlg);
    
    abMacDataBuf[0] = lpCtx->bSvType << 6;
    abMacDataBuf[0] |= (lpstAlg->eAlgId >> 4) & 0x3F;
    abMacDataBuf[1] = lpstAlg->eAlgId << 4;
    abMacDataBuf[1] |= (lpstKey->dwKeyId >> 16) & 0xF;
    abMacDataBuf[2] = lpstKey->dwKeyId >> 8;
    abMacDataBuf[3] = lpstKey->dwKeyId;

    switch(lpCtx->bSvType) {
    case 0:
        // Copy 9-byte PIV and plaintext
        dwMacDataHdrLen = 4+9;
        memcpy(&abMacDataBuf[4], lpCtx->abSdsPiv, 9);
        memcpy(&abMacDataBuf[4 + 9], lpCtx->abPt, dwPtLenBytes);
        break;

    case 1:
        // Copy 9-byte PIV, 3-byte IV-EXT and plaintext
        dwMacDataHdrLen = 4 + 9 + 3;
        memcpy(&abMacDataBuf[4], lpCtx->abSdsPiv, 9);
        memcpy(&abMacDataBuf[4 + 9], lpCtx->abSenderIssi, 3);
        memcpy(&abMacDataBuf[4+9+3], lpCtx->abPt, dwPtLenBytes);
        break;

    case 2: 
        // Copy 4-byte PIV and plaintext
        dwMacDataHdrLen = 4+4;
        memcpy(&abMacDataBuf[4], lpCtx->abSdsPiv, 4);
        memcpy(&abMacDataBuf[dwMacDataHdrLen], lpCtx->abPt, dwPtLenBytes);
        break;
    default:
        assert(false);
    }

    uint32_t dwNumBlocksForKs = (dwPtLenBytes + lpstAlg->bBlockSize - 1) / lpstAlg->bBlockSize;
    uint32_t dwNumBlocksForMac = (dwPtLenBytes + (lpstAlg->bBlockSize - 1) + dwMacDataHdrLen) / lpstAlg->bBlockSize;
    uint32_t dwNumBytesForMac = dwNumBlocksForMac * lpstAlg->bBlockSize;
    
    if (dwNumBytesForMac >= 185) {
        return false;
    }
    
    pad_end_of_ccsum_fields(abMacDataBuf, (8 * dwMacDataHdrLen + lpCtx->dwPtLenBits), dwNumBytesForMac);
    etee_e6(abMacKey, abMacDataBuf, dwNumBlocksForMac, lpCtx->abMac1, lpCtx->abMac2, lpstAlg->eAlgId);
    assemble_iv(lpCtx->abFullIv, lpCtx->bSvType, lpCtx->abSdsPiv, lpCtx->abMac1, lpCtx->abSenderIssi, lpstAlg->bBlockSize);
    
    uint8_t _abNextPiv[9];
    etee_e5(lpstKey->abKey, lpCtx->abFullIv, lpCtx->abSdsKs, lpstKey->eAlgId, dwNumBlocksForKs, _abNextPiv);
    
    memcpy(lpCtx->abSdsCt, lpCtx->abPt, dwPtLenBytes);
    xor_bits(lpCtx->abSdsCt, lpCtx->abSdsKs, lpCtx->dwPtLenBits);
    
    memcpy(&lpPackedOut[0], abMacDataBuf, 4);
    memcpy(&lpPackedOut[4], lpCtx->abSdsPiv, dwPivLen);
    memcpy(&lpPackedOut[4+dwPivLen], lpCtx->abMac1, 4);
    memcpy(&lpPackedOut[4+dwPivLen+4], lpCtx->abSdsCt, dwPtLenBytes);
    
    generate_accsum(lpCtx->abCcsum, lpstKey->abKey, lpCtx->abPt[0], lpCtx->dwNonce, lpCtx->abMac2, lpstKey->eAlgId);

    return true;
}

bool etee_sds_decrypt(const uint8_t *lpBuf, uint32_t dwBufLenBits, EteeSdsCtx *lpCtx) {

    const EteeKey *lpstKey = lpCtx->lpstKey;
    const EteeAlg *lpstAlg = get_alg_properties(lpstKey->eAlgId);
    
    lpCtx->bSvType = lpBuf[0] >> 6;
    uint16_t eAlgId = ((lpBuf[0] & 0x3F) << 4) | (lpBuf[1] >> 4);
    uint32_t dwKeyId = ((lpBuf[1] & 0x0F) << 16) | (lpBuf[2] << 8) | lpBuf[3];

    uint32_t dwPivLen = (lpCtx->bSvType == 2 ? 4 : 9);
    lpCtx->dwPtLenBits = dwBufLenBits - 2 - 10 - 20 - dwPivLen*8 - 32; 
    uint32_t dwPtLenBytes = (lpCtx->dwPtLenBits + 7) / 8;
    uint32_t dwKeylenBytes = lpstKey->wKeyLenBits / 8;
    
    assert(dwBufLenBits > 2+10+20+dwPivLen*8+32);
    assert(eAlgId == lpstKey->eAlgId);
    assert(dwKeyId == lpstKey->dwKeyId);
    assert(dwBufLenBits % 8 == 0); 
    
    memcpy(lpCtx->abSdsPiv, &lpBuf[4], dwPivLen);
    memcpy(lpCtx->abMac1_extracted, &lpBuf[4+dwPivLen], 4);
    memcpy(lpCtx->abSdsCt, &lpBuf[4+dwPivLen+4], dwPtLenBytes);
    memcpy(lpCtx->abCcsum, &lpBuf[4+dwPivLen+4+dwPtLenBytes], 4);

    uint8_t abIv[16];
    assemble_iv(abIv, lpCtx->bSvType, lpCtx->abSdsPiv, lpCtx->abMac1_extracted, lpCtx->abSenderIssi, lpstAlg->bBlockSize);
    
    uint8_t _abNextPiv[9];
    uint32_t dwNumBlocksForKs = (dwPtLenBytes + lpstAlg->bBlockSize - 1) / lpstAlg->bBlockSize;
    etee_e5(lpstKey->abKey, abIv, lpCtx->abSdsKs, lpstKey->eAlgId, dwNumBlocksForKs, _abNextPiv);
    memcpy(lpCtx->abPt, lpCtx->abSdsCt, dwPtLenBytes);
    xor_bits(lpCtx->abPt, lpCtx->abSdsKs, lpCtx->dwPtLenBits);

    // We have now successfully decrypted the message. We can now perform the integrity test.

    uint8_t abMacDataBuf[256];
    uint32_t dwMacDataHdrLen;

    abMacDataBuf[0] = lpCtx->bSvType << 6;
    abMacDataBuf[0] |= (lpstAlg->eAlgId >> 4) & 0x3F;
    abMacDataBuf[1] = lpstAlg->eAlgId << 4;
    abMacDataBuf[1] |= (lpstKey->dwKeyId >> 16) & 0xF;
    abMacDataBuf[2] = lpstKey->dwKeyId >> 8;
    abMacDataBuf[3] = lpstKey->dwKeyId;

    switch(lpCtx->bSvType) {
    case 0:
        // Copy 9-byte PIV and plaintext
        dwMacDataHdrLen = 4+9;
        memcpy(&abMacDataBuf[4], lpCtx->abSdsPiv, 9);
        memcpy(&abMacDataBuf[4 + 9], lpCtx->abPt, dwPtLenBytes);
        break;

    case 1:
        // Copy 9-byte PIV, 3-byte IV-EXT and plaintext
        dwMacDataHdrLen = 4+9+3;
        memcpy(&abMacDataBuf[4], lpCtx->abSdsPiv, 9);
        memcpy(&abMacDataBuf[4 + 9], lpCtx->abSenderIssi, 3);
        memcpy(&abMacDataBuf[4+9+3], lpCtx->abPt, dwPtLenBytes);
        break;

    case 2: 
        // Copy 4-byte PIV and plaintext
        dwMacDataHdrLen = 4+4;
        memcpy(&abMacDataBuf[4], lpCtx->abSdsPiv, 4);
        memcpy(&abMacDataBuf[4+4], lpCtx->abPt, dwPtLenBytes);
        break;
    default: 
        assert(false);
    }

    uint8_t abMacKey[dwKeylenBytes], abXorredTek[dwKeylenBytes];
    memcpy(abXorredTek, lpstKey->abKey, dwKeylenBytes);
    xor_bytes(abXorredTek, g_abSdsKeyProcessingIv, dwKeylenBytes);
    derive_mac_key(abMacKey, abXorredTek, lpstAlg);

    uint32_t dwNumBlocksForMac = ((lpCtx->dwPtLenBits + 8) / 8 + (lpstAlg->bBlockSize - 1) + dwMacDataHdrLen) / lpstAlg->bBlockSize;
    uint32_t dwNumBytesForMac = dwNumBlocksForMac * lpstAlg->bBlockSize;
    if (dwNumBytesForMac >= 185) {
        return false;
    }
    
    pad_end_of_ccsum_fields(abMacDataBuf, (8 * dwMacDataHdrLen + lpCtx->dwPtLenBits), dwNumBytesForMac);
    etee_e6(abMacKey, abMacDataBuf, dwNumBlocksForMac, lpCtx->abMac1, lpCtx->abMac2, lpstAlg->eAlgId);
    generate_accsum(lpCtx->abCcsum, lpstKey->abKey, lpCtx->abPt[0], lpCtx->dwNonce, lpCtx->abMac2, lpstKey->eAlgId);

    return memcmp(lpCtx->abMac1_extracted, lpCtx->abMac1, 4) == 0;
}
