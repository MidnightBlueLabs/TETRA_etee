#pragma once

#include <inttypes.h>
#include <stdbool.h>

/* Identifiers as used on the air interface */
enum tetra_etee_algid {
    ETEE_ALG_UNDEFINED =    0,
    ETEE_ALG_AES56  =       0x87,
    ETEE_ALG_AES128 =       0x89,
    ETEE_ALG_AES256 =       0x8A,
    ETEE_ALG_IDEA 	=       0x80
};

typedef struct {
    enum tetra_etee_algid eAlgId;
    char szAlgName[8];
    uint8_t bKeySize;   /* Key size in bytes */
    uint8_t bBlockSize;
} EteeAlg;

typedef struct {
    enum tetra_etee_algid eAlgId;
    uint32_t dwKeyId;
    uint8_t bKeyIsLoaded;
    uint16_t wKeyLenBits;
    uint8_t abKey[32];
} EteeKey;

typedef struct {
    EteeKey stKek;       /* Used for unsealing keys */
    EteeKey stSek;       /* Used for decrypting KmmReq buffers */
    EteeKey astTeks[3];  /* Used for traffic encryption/decryption */
} EteeKeystore;

typedef struct {
    /* Always supply: */
    EteeKey *lpstKey;

    /* For encryption, also supply: */
    uint8_t bSvType;            /* 0: 9 byte PIV  1: 9-byte PIV + ISSI  2: 4-byte PIV */
    uint8_t abSenderIssi[3];    /* Only for SvType == 1 */
    uint8_t abSdsPiv[9];        /* Only 4 bytes for SvType == 2 */

    // For type 2, supply:
    uint32_t dwNonce;           /* 24 bit */

    /* The following fields are for debugging/educational purposes only */
    uint8_t abPt[256];
    uint32_t dwPtLenBits;
    uint8_t abSdsKs[256];
    uint8_t abSdsCt[256];
    uint8_t abFullIv[16];
    uint8_t abMac1_extracted[4];
    uint8_t abMac1[4];
    uint8_t abMac2[4];
    uint8_t abSdsNewPiv[9];         /* Contains updated SdsPiv usable for next request */
    uint8_t abPackedSv[17];         /* Contains packed AlgId,KeyId,IV plus MAC1 */
    uint8_t abCcsum[4];             /* Cryptographic checksum */
} EteeSdsCtx;

typedef struct {
    uint8_t bEncrypt;                   /* Set to true for encryption, false for decryption */
    enum tetra_etee_algid wKekAlgId;
    uint16_t dwKekId;
    uint8_t abIv[16];
    uint32_t dwBufLen;
    uint8_t abPtBuf[160];
    uint8_t abCtBuf[160];
} EteeKmmReq;

/**
 * @brief Retrieves algorithm properties for a given TETRA ETEE algorithm ID
 * @param eAlgId The TETRA ETEE algorithm identifier
 * @return Pointer to EteeAlg struct containing algorithm properties, or NULL if invalid
 */
const EteeAlg *get_alg_properties(enum tetra_etee_algid eAlgId);

/**
 * @brief Generates a synchronization frame for traffic encryption
 * @param lpstTek Pointer to Traffic Encryption Key (TEK) struct
 * @param lpIv Pointer to IV data (length depends on algorithm)
 * @param lpOut Pointer to output buffer for generated sync frame (length depends on config)
 */

void etee_generate_syncframe(const EteeKey *lpstTek, const uint8_t *lpIv, uint8_t *lpOut);

/**
 * @brief Unpacks and validates a synchronization, selecting the right TEK from a list of keys. 
 * @param lpstKeys Pointer to array of available encryption keys
 * @param dwNumKeys Number of keys in the lpstKeys array
 * @param lpFrameIn Pointer to input sync frame data
 * @param lpIvOut Pointer to output buffer for extracted initialization vector
 * @return Pointer to matching EteeKey if successful, NULL if frame cannot be unpacked (key not found, incorrect format, etc)
 */
const EteeKey *etee_unpack_syncframe(const EteeKey *lpstKeys, uint32_t dwNumKeys, const uint8_t *lpFrameIn, uint8_t *lpIvOut);


/**
 * @brief Encrypts Short Data Service (SDS) data
 * @param lpPackedOut Pointer to output buffer for encrypted packed data
 * @param lpCtx Pointer to SDS encryption context struct
 * @return true if encryption successful, false otherwise (eg invalid algo, plaintext too long)
 */
bool etee_sds_encrypt(uint8_t *lpPackedOut, EteeSdsCtx *lpCtx);

/**
 * @brief Decrypts E2EE-encrypted Short Data Service (SDS) data
 * @param lpBuf Pointer to input buffer containing encrypted data
 * @param dwBufLenBits Length of input buffer in bits
 * @param lpCtx Pointer to SDS decryption context struct
 * @return true if decryption successful, false otherwise)
 */
bool etee_sds_decrypt(const uint8_t *lpBuf, uint32_t dwBufLenBits, EteeSdsCtx *lpCtx);

/**
 * @brief Seals (encrypts) a Traffic Encryption Key using a Key Encryption Key
 * @param lpKek Pointer to KEK struct
 * @param lpTek Pointer to TEK to be sealed
 * @param lpSealedOut Pointer to output buffer for sealed key data
 * @return true if sealing successful, false otherwise
 */
bool etee_seal_tek(EteeKey *lpKek, EteeKey *lpTek, uint8_t *lpSealedOut);

/**
 * @brief Unseals (decrypts) a Traffic Encryption Key using a Key Encryption Key
 * @param lpKek Pointer to KEK struct
 * @param lpTekInOut Pointer to TEK struct for input/output. Set expected eAlgId and dwKeyId before calling.
 * @param lpSealedIn Pointer to input sealed key data
 * @param lpUnsealedOut Pointer to output buffer for unsealed key data
 * @return true if unsealing successful, false otherwise
 */
bool etee_unseal_tek(EteeKey *lpKek, EteeKey *lpTekInOut, uint8_t *lpSealedIn, uint8_t *lpUnsealedOut);

/**
 * @brief Processes a Key Management Message (KMM) request
 * @param lpstKeystore Pointer to keystore struct containing available keys
 * @param lpCtx Pointer to KMM request context struct
 * @return true if KMM request processed successfully, false otherwise
 */
bool etee_kmm_req(EteeKeystore *lpstKeystore, EteeKmmReq *lpCtx);
