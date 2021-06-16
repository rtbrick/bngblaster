/*
 * BNG Blaster (BBL) - Utils
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_utils.h"

const char *
val2key (struct keyval_ *keyval, uint val)
{
    int idx;
    idx = 0;
    while (keyval[idx].key) {
        if (val == keyval[idx].val) {
            return keyval[idx].key;
        }
        idx++;
    }
    return "Unknown";
}

char *
format_mac_address (uint8_t *mac)
{
    static char buffer[32][MAC_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 31;
    snprintf(ret, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ret;
}

/*
 * Format an IPv4 address as string in one of 16 buffers.
 */
char *
format_ipv4_address (uint32_t *addr4)
{
    static char buffer[32][IPV4_DOTTED_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 31;
    inet_ntop(AF_INET, addr4, ret, IPV4_DOTTED_STR_LEN);
    return ret;
}

/*
 * Format an IPv6 address as string in one of 16 buffers.
 */
char *
format_ipv6_address (ipv6addr_t *addr6)
{
    static char buffer[16][IPV6_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 15;
    inet_ntop(AF_INET6, addr6, ret, IPV6_STR_LEN);
    return ret;
}

/*
 * Format an IPv6 prefix as string in one of 16 buffers.
 */
char *
format_ipv6_prefix (ipv6_prefix *addr6)
{
    static char buffer[16][IPV6_PREFIX_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 15;
    inet_ntop(AF_INET6, addr6->address, ret, IPV6_STR_LEN);
    snprintf(ret + strlen(ret), 5, "/%d", addr6->len);
    return ret;
}

char *
replace_substring (const char* source,
                   const char* old,
                   const char* new)
{
    if(!(source && old && new)) {
        return NULL;
    }

    static char buffer[4][STRLEN_MAX];
    static int idx = 0;
    char  *result = buffer[idx];
    char  *result_pos = result;
    size_t result_len = 0;

    idx = (idx+1) & 4;
    
    size_t new_len = strlen(new);
    size_t old_len = strlen(old);

    const char *cur = source;
    const char *sub;
    size_t c;

    while(cur && *cur != '\0') {
        sub = strstr(cur, old);
        if(sub) {
            c = sub - cur;
            result_len += c + new_len;
            if(result_len < STRLEN_MAX) {
                memcpy(result_pos, cur, c);
                result_pos += c;
                memcpy(result_pos, new, new_len);
                result_pos += new_len;
            }
            cur = sub + old_len;
        } else {
            c = strlen(cur);
            result_len += c;
            if(result_len < STRLEN_MAX) { 
                memcpy(result_pos, cur, c);
                result_pos += c;
            }
            cur = NULL;
        }
    }
    *result_pos = '\0';
    return result;
}
