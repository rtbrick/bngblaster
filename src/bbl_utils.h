/*
 * BNG Blaster (BBL) - Utils
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_UTILS_H__
#define __BBL_UTILS_H__

#define STRLEN_MAX                  256
#define MAC_STR_LEN                 sizeof("00:00:00:00:00:00")
#define IPV4_DOTTED_STR_LEN         sizeof("255.255.255.255")
#define IPV6_STR_LEN                sizeof("0000:0000:0000:0000:0000:0000:0000:0000")
#define IPV6_PREFIX_STR_LEN         sizeof("0000:0000:0000:0000:0000:0000:0000:0000/128")

char *format_mac_address(uint8_t *mac);
char *format_ipv4_address(uint32_t *addr4);
char *format_ipv6_address(ipv6addr_t *addr6);
char *format_ipv6_prefix(ipv6_prefix *addr6);

char *replace_substring (const char* s, const char* old, const char* new);
const char *val2key (struct keyval_ *keyval, uint val);
#endif
