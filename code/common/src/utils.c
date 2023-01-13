/*
 * Utils
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "utils.h"

/*
 * Simple big endian reader.
 */
uint64_t
read_be_uint(uint8_t *data, size_t length)
{
    uint32_t idx;
    uint64_t value = 0;

    if (!length || length > sizeof(value)) {
        return 0;
    }
    for (idx = 0; idx < length; idx++) {
        value <<= 8;
        value = value | *(data+idx);
    }
    return value;
}

/*
 * Simple big endian writer.
 */
bool
write_be_uint(uint8_t *data, size_t length, uint64_t value)
{
    uint32_t idx;

    if (!length || length > 8) {
        return false;
    }

    for (idx = 0; idx < length; idx++) {
        data[length - idx -1] =  value & 0xff;
        value >>= 8;
    }
    return true;
}

/*
 * Push a big endian integer to the write buffer and update the cursor.
 */
bool
push_be_uint(io_buffer_t *buffer, size_t length, uint64_t value)
{
    /*
     * Buffer overrun protection.
     */
    if ((buffer->idx + length) > buffer->size) {
        return false;
    }

    /*
     * Write the data.
     */
    write_be_uint(buffer->data + buffer->idx, length, value);

    /*
     * Adjust the cursor.
     */
    buffer->idx += length;
    return true;
}

/*
 * Push a continuous set of data to the write buffer and update the cursor.
 */
bool
push_data(io_buffer_t *buffer, uint8_t *data, size_t length)
{
    /*
     * Buffer overrun protection.
     */
    if ((buffer->idx + length) > buffer->size) {
        return false;
    }

    /*
     * Copy the data.
     */
    memcpy(buffer->data + buffer->idx, data, length);

    /*
     * Adjust the cursor.
     */
    buffer->idx += length;
    return true;
}

/*
 * Simple little endian writer.
 */
bool
write_le_uint(uint8_t *data, uint32_t length, uint64_t value)
{
    uint32_t idx;

    if (!length || length > 8) {
        return false;
    }

    for (idx = 0; idx < length; idx++) {
        data[idx] = value & 0xff;
        value >>= 8;
    }
    return true;
}

/*
 * Push a little endian integer to the write buffer and update the cursor.
 */
bool
push_le_uint(io_buffer_t *buffer, uint32_t length, uint64_t value)
{
    /*
     * Buffer overrun protection.
     */
    if ((buffer->idx + length) > buffer->size) {
        return false;
    }

    /*
     * Write the data.
     */
    write_le_uint(buffer->data + buffer->idx, length, value);

    /*
     * Adjust the cursor.
     */
    buffer->idx += length;
    return true;
}

const char *
val2key(struct keyval_ *keyval, uint32_t val) 
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

uint32_t
key2val(struct keyval_ *ptr, const char *key)
{
    while (ptr->key) {
        if (strcmp(ptr->key, key) == 0) {
            return ptr->val;
        }
        ptr++;
    }
    return 0;
}

const char *
keyval_get_key (struct keyval_ *keyval, uint32_t val)
{
    struct keyval_ *ptr;

    ptr = keyval;
    while (ptr->key) {
        if (ptr->val == val) {
            return ptr->key;
        }
        ptr++;
    }
    return "unknown";
}

/**
 * format_mac_address
 *
 * Format an MAC address as string in one of 16 static buffers.
 *
 * @param mac IPv4 address bytes
 * @return MAC address string
 */
char *
format_mac_address(uint8_t *mac) 
{
    static char buffer[16][MAC_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 15;
    snprintf(ret, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ret;
}

/**
 * format_ipv4_address
 *
 * Format an IPv4 address as string in one of 32 static buffers.
 *
 * @param addr4 IPv4 address bytes
 * @return IPv4 address string
 */
char *
format_ipv4_address(uint32_t *addr4)
{
    static char buffer[32][IPV4_DOTTED_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    *ret = '\0';
    idx = (idx+1) & 31;
    inet_ntop(AF_INET, addr4, ret, IPV4_DOTTED_STR_LEN);
    return ret;
}

/**
 * format_ipv4_prefix
 *
 * Format an IPv4 prefix as string in one of 16 static buffers.
 *
 * @param addr4 IPv4 prefix bytes
 * @return IPv4 prefix string
 */
char *
format_ipv4_prefix(ipv4_prefix *addr4)
{
    static char buffer[16][IPV4_DOTTED_PREFIX_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    *ret = '\0';
    idx = (idx+1) & 15;
    inet_ntop(AF_INET, &addr4->address, ret, IPV4_DOTTED_STR_LEN);
    snprintf(ret + strlen(ret), 5, "/%d", addr4->len);
    return ret;
}

/**
 * format_ipv6_address
 *
 * Format an IPv6 address as string in one of 16 static buffers.
 *
 * @param addr6 IPv6 address bytes
 * @return IPv6 address string
 */
char *
format_ipv6_address(ipv6addr_t *addr6)
{
    static char buffer[16][IPV6_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    *ret = '\0';
    idx = (idx+1) & 15;
    inet_ntop(AF_INET6, addr6, ret, IPV6_STR_LEN);
    return ret;
}

/**
 * format_ipv6_prefix
 *
 * Format an IPv6 prefix as string in one of 16 static buffers.
 *
 * @param addr6 IPv6 prefix bytes
 * @return IPv6 prefix string
 */
char *
format_ipv6_prefix(ipv6_prefix *addr6)
{
    static char buffer[16][IPV6_PREFIX_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    *ret = '\0';
    idx = (idx+1) & 15;
    inet_ntop(AF_INET6, addr6->address, ret, IPV6_STR_LEN);
    snprintf(ret + strlen(ret), 5, "/%d", addr6->len);
    return ret;
}

/**
 * format_iso_prefix
 *
 * Format an ISO prefix as string in one of 16 static buffers.
 *
 * @param iso ISO prefix structure
 * @return ISO prefix string
 */
char *
format_iso_prefix(iso_prefix *iso)
{
    char hextable[] = "0123456789abcdef";
    uint8_t hi_byte, lo_byte;
    uint16_t i, buf_idx, prefix_len;

    static char buffer[16][ISO_STR_LEN];
    static int idx = 0;
    char *ret;

    ret = buffer[idx];
    *ret = '\0';
    idx = (idx+1) & 15;

    if (iso->len > (sizeof(iso->address)*8)) {
        return ret;
    }

    buf_idx = 0;
    prefix_len = (iso->len+7)/8;
    for (i = 0; i < prefix_len; i++) {
        hi_byte = iso->address[i] >> 4;
        lo_byte = iso->address[i] & 0xf;

        ret[buf_idx++] = hextable[hi_byte];
        ret[buf_idx++] = hextable[lo_byte];

        if (((i & 1) == 0) && (i + 1 < prefix_len)) {
            ret[buf_idx++] = '.';
        }
    }
    snprintf(ret+buf_idx, ISO_STR_LEN-buf_idx, "/%u", iso->len);
    return ret;
}

/**
 * scan_ipv4_prefix
 *
 * Scan an IPv4 prefix from string into prefix structure.
 *
 * @param str IPv4 source string
 * @param ipv4 IPv4 target structure
 * @return true if successfully
 */
bool
scan_ipv4_prefix(const char *str, ipv4_prefix *ipv4) 
{
    char *s = strdup(str);
    char *p;
    int   r = 0;

    p = strchr(s, '/');
    if(p) {
        sscanf(p, "/%hhu", &ipv4->len);
        *p = '\0';
        if(ipv4->len > 32) {
            free(s);
            return false;
        }
    } else {
        ipv4->len = 24;
    }

    r = inet_pton(AF_INET, s, &ipv4->address);
    free(s);
    if(!r) {
        return false;
    }
    return true;
}

/**
 * scan_ipv4_address
 *
 * Scan an IPv4 address from string into address structure.
 *
 * @param str IPv4 source string
 * @param ipv4 IPv4 target structure
 * @return true if successfully
 */
bool
scan_ipv4_address(const char *str, uint32_t *ipv4) 
{
    if(!inet_pton(AF_INET, str, ipv4)) {
        return false;
    }
    return true;
}

/**
 * scan_ipv6_prefix
 *
 * Scan an IPv6 prefix from string into prefix structure.
 *
 * @param str IPv6 source string
 * @param ipv6 IPv6 target structure
 * @return true if successfully
 */
bool
scan_ipv6_prefix(const char *str, ipv6_prefix *ipv6)
{
    char *s = strdup(str);
    char *p;
    int   r;

    p = strchr(s, '/');
    if(p) {
        sscanf(p, "/%hhu", &ipv6->len);
        *p = '\0';
        if(ipv6->len > 128) {
            free(s);
            return false;
        }
    } else {
        ipv6->len = 64;
    }

    r = inet_pton(AF_INET6, s, &ipv6->address);
    free(s);
    if(!r) {
        return false;
    }
    return true;
}

/**
 * scan_ipv6_address
 *
 * Scan an IPv6 address from string into address structure.
 *
 * @param str IPv6 source string
 * @param ipv6 IPv6 target structure
 * @return true if successfully
 */
bool
scan_ipv6_address(const char *str, ipv6addr_t *ipv6)
{
    if(!inet_pton(AF_INET6, str, ipv6)) {
        return false;
    }
    return true;
}

/**
 * scan_iso_prefix
 *
 * Scan an ISO prefix from string into prefix structure.
 *
 * @param str ISO source string
 * @param iso ISO target structure
 * @return true if successfully
 */
bool
scan_iso_prefix(const char *str, iso_prefix *iso)
{
    char *tok;
    char *save = NULL;
    char *s;
    char  c;

    uint16_t idx;
    uint16_t len;
    uint16_t digit = 0;
    uint16_t val = 0;
    uint16_t prefix_idx = 0;

    if(!(str && iso)) {
        return false;
    }

    s = strdup(str);

    memset(iso, 0, sizeof(iso_prefix));
    tok = strtok_r(s, "/", &save);
    if (!tok) {
        free(s);
        return false;
    }

    len = strlen(s);
    for (idx = 0; idx < len; idx++) {

        c = s[idx];

        if (c >= '0' && c <= '9') {
            val = (val << 4) | (c - '0');
            digit++;
        }
        if (c >= 'a' && c <= 'f') {
            val = (val << 4) | (c - 'a');
            digit++;
        }
        if (c >= 'A' && c <= 'F') {
            val = (val << 4) | (c - 'A');
            digit++;
        }

        if (prefix_idx >= sizeof(iso->address)) {
            free(s);
            return false;
        }

        if (digit == 2) {
            iso->address[prefix_idx++] = (val & 0xff);
            digit = 0;
        }
    }

    tok = strtok_r(NULL, "/", &save);
    if (tok) {
        iso->len = atoi(tok);
    }
    free(s);
    return true;
}

/**
 * ipv4_multicast_mac
 *
 * @param ipv4 IPv4 multicast address
 * @param mac target buffer to store multicast MAC
 */
void
ipv4_multicast_mac(const uint32_t ipv4, uint8_t* mac) 
{
    *(uint32_t*)(&mac[2]) = ipv4;
    mac[0] = 0x01;
    mac[1] = 0x00;
    mac[2] = 0x5e;
    mac[3] &= 0x7f;
}

/**
 * ipv6_multicast_mac
 *
 * @param ipv6 IPv6 multicast address
 * @param mac target buffer to store multicast MAC
 */
void
ipv6_multicast_mac(const uint8_t *ipv6, uint8_t* mac) 
{
    *(uint32_t*)(&mac[2]) =*(uint32_t*)(&ipv6[12]);
    mac[0] = 0x33;
    mac[1] = 0x33;
}

/**
 * ipv6_addr_not_zero
 *
 * @param addr IPv6 address
 * @return true if IPv6 is not zero (!::)
 */
bool
ipv6_addr_not_zero(ipv6addr_t *addr)
{
    if(addr && (*(uint64_t *)addr != 0 ||*((uint64_t *)addr + 1) != 0 )) {
        return true;
    }
    return false;
}

/**
 * ipv6_prefix_not_zero
 *
 * @param prefix IPv6 prefix
 * @return true if IPv6 prefix length and address are not zero (!::/0)
 */
bool
ipv6_prefix_not_zero(ipv6_prefix *prefix) 
{
    /* check if pointer and prefix length */
    if(prefix && *(uint8_t*)prefix > 0) {
        return ipv6_addr_not_zero((ipv6addr_t *)prefix+1);
    }
    return false;
}

/**
 * replace_substring
 *
 * Replace subscrtring in one of 4 static buffers.
 *
 * @param source source string
 * @param old subsctring to search for
 * @param new subsctring to replace with
 * @return new string
 */
char *
replace_substring(const char* source,
                  const char* old,
                  const char* new)
{
    if(!(source && old && new)) {
        return NULL;
    }

    static char buffer[4][SUB_STR_LEN];
    static int idx = 0;
    char  *result = buffer[idx];
    char  *result_pos = result;
    size_t result_len = 0;

    idx = (idx+1) & 3;

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
            if(result_len < SUB_STR_LEN) {
                memcpy(result_pos, cur, c);
                result_pos += c;
                memcpy(result_pos, new, new_len);
                result_pos += new_len;
            }
            cur = sub + old_len;
        } else {
            c = strlen(cur);
            result_len += c;
            if(result_len < SUB_STR_LEN) {
                memcpy(result_pos, cur, c);
                result_pos += c;
            }
            cur = NULL;
        }
    }
    *result_pos = '\0';
    return result;
}

char *
string_or_na(char *string)
{
    if(string) {
        return string;
    } else {
        return "N/A";
    }
}