/*
 * LSPGEN - HMAC MD5
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <strings.h>

/**
 * @brief 
 * 
 * @param text pointer to data stream
 * @param text_len length of data stream
 * @param key pointer to authentication key
 * @param key_len length of authentication key
 * @param digest caller digest to be filled in
 */
void
hmac_md5(unsigned char* text, int text_len, 
         unsigned char* key, int key_len, 
         uint8_t* digest)
{
    HMAC_CTX *hmac = HMAC_CTX_new();
    HMAC_Init_ex(hmac, key, key_len, EVP_md5(), NULL);
    HMAC_Update(hmac, text, text_len);
    HMAC_Final(hmac, digest, NULL);
    HMAC_CTX_free(hmac);
}