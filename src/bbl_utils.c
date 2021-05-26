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
replace_substring (const char* s,
                   const char* old,
                   const char* new)
{
    static char result[STRLEN_MAX];

    int i, cnt = 0;
    size_t new_len = strlen(new);
    size_t old_len = strlen(old);

    /* Counting the number of times old
     * occur in the string*/
    for (i = 0; s[i] != '\0'; i++) {
        if (strstr(&s[i], old) == &s[i]) {
            cnt++;
            /* Jumping to index after the old word */
            i += old_len - 1;
        }
    }

    /* Check if string fits into buffer */
    if((i + cnt * (new_len - old_len) + 1) >= STRLEN_MAX) {
        return NULL;
    }

    i = 0;
    while (*s) {
        /* Compare the substring with the result */
        if (strstr(s, old) == s) {
            strcpy(&result[i], new);
            i += new_len;
            s += old_len;
        } else {
            result[i++] = *s++;
        }
    }

    result[i] = '\0';
    return result;
}
