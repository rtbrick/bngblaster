/*
 * LSPGEN - HMAC MD5
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __HMAC_MD5_H__
#define __HMAC_MD5_H__

void
hmac_md5(unsigned char* text, int text_len,
         unsigned char*key, int key_len,
         uint8_t* digest);

#endif