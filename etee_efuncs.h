#pragma once

#include <stdbool.h>
#include <inttypes.h>

#include "etee.h"

/**
 * @brief Performs ETEE E1 operation - Traffic key stream generation with IV update
 * @param lpKey Pointer to the TEK
 * @param lpIvInOut Pointer to IV (input/output, set to IV for next frame)
 * @param lpKsOut Pointer to output buffer for generated key stream
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 */
void etee_e1(const uint8_t *lpKey, uint8_t *lpIvInOut, uint8_t *lpKsOut, enum tetra_etee_algid eAlgId);

/**
 * @brief Performs ETEE E2 operation - TEK sealing
 * @param lpKey Pointer to the encryption key
 * @param lpCtIn Pointer to input ciphertext blocks
 * @param lpPtOut Pointer to output buffer for unsealed buffer
 * @param dwNumBlocks Number of blocks to decrypt
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 */
void etee_e2(const uint8_t *lpKey, const uint8_t *lpCtIn, uint8_t *lpPtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId);

/**
 * @brief Performs ETEE E2 inverse operation - TEK unsealing
 * @param lpKey Pointer to the encryption key
 * @param lpPtIn Pointer to input plaintext blocks
 * @param lpCtOut Pointer to output buffer for sealed buffer
 * @param dwNumBlocks Number of blocks to encrypt
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 */
void etee_e2_inv(const uint8_t *lpKey, const uint8_t *lpPtIn, uint8_t *lpCtOut, uint32_t dwNumBlocks, enum tetra_etee_algid eAlgId);

/**
 * @brief Performs ETEE E3 operation - Traffic syncframe MAC computation
 * @param lpKey Pointer to the encryption key
 * @param lpInOut Pointer to data buffer (input/output)
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 */
void etee_e3(const uint8_t *lpKey, uint8_t *lpInOut, enum tetra_etee_algid eAlgId);

/**
 * @brief Performs ETEE E4 operation - KMM sealing/unsealing
 * @param lpKey Pointer to the encryption key
 * @param lpIvIn Pointer to initialization vector (input only)
 * @param lpInOut Pointer to data buffer (input/output)
 * @param dwNumBlocks Number of blocks to process
 * @param bEncrypt Flag indicating encryption (1) or decryption (0)
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 */
void etee_e4(const uint8_t *lpKey, const uint8_t *lpIvIn, uint8_t *lpInOut, uint32_t dwNumBlocks, uint8_t bEncrypt, enum tetra_etee_algid eAlgId);

/**
 * @brief Performs ETEE E5 operation - SDS key stream generation
 * @param lpKey Pointer to the encryption key
 * @param lpIv Pointer to initialization vector
 * @param lpKs_out Pointer to output buffer for generated key stream
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 * @param dwNumBlocks Number of key stream blocks to generate
 * @param lpNextPiv_out Pointer to output buffer for next processed IV
 */
void etee_e5(const uint8_t *lpKey, const uint8_t *lpIv, uint8_t *lpKs_out, enum tetra_etee_algid eAlgId, uint32_t dwNumBlocks, uint8_t *lpNextPiv_out);

/**
 * @brief Performs ETEE E6 operation - SDS MAC computation
 * @param lpKey Pointer to the encryption key
 * @param lpIn Pointer to input data blocks
 * @param dwNumBlocks Number of input blocks to process
 * @param lpMac1 Pointer to output buffer for first MAC value
 * @param lpMac2 Pointer to output buffer for second MAC value
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 */
void etee_e6(const uint8_t *lpKey, const uint8_t *lpIn, uint32_t dwNumBlocks, uint8_t *lpMac1, uint8_t *lpMac2, enum tetra_etee_algid eAlgId);

/**
 * @brief Encrypts or decrypts a single block using ETEE algorithm
 * @param lpIn Pointer to input block data
 * @param lpKey Pointer to the encryption key
 * @param lpOut Pointer to output buffer for processed block
 * @param bEncrypt Flag indicating encryption (1) or decryption (0)
 * @param eAlgId Algorithm identifier specifying which ETEE algorithm to use
 */
void etee_crypt_blk(const uint8_t *lpIn, const uint8_t *lpKey, uint8_t *lpOut, int32_t bEncrypt, enum tetra_etee_algid eAlgId);

/**
 * @brief Processes and transforms an encryption key for ETEE usage. Only actually does something for AES-56.
 * @param lpKeyInOut Pointer to key buffer (input/output)
 * @param eAlgId Algorithm identifier specifying the ETEE algorithm
 */
void etee_process_key(uint8_t *lpKeyInOut, enum tetra_etee_algid eAlgId);
