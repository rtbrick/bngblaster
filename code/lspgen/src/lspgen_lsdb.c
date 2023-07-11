/*
 * Generic LSDB implementation for link-state protocols.
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"

/*
 * Convert the node_id string to binary data.
 */
void
lsdb_scan_node_id(uint8_t *node_id, char *node_id_str)
{
    char input_val, val;
    int dst_idx, reg;
    unsigned int idx, len;

    dst_idx = 0;
    reg = 0;
    len = strlen(node_id_str);
    for (idx = 0; idx < len; idx++) {
        input_val = *(node_id_str+idx);
        val = 0;
        if (input_val >= '0' && input_val <= '9') {
            val = input_val - '0';
        } else if (input_val >= 'a' && input_val <= 'f') {
            val = input_val - 'a' + 10;
        } else if (input_val >= 'A' && input_val <= 'F') {
            val = input_val - 'A' + 10;
        } else {
            continue; /* non hex character */
        }
        reg <<= 4;
        reg |= val;
        node_id[dst_idx >> 1] = reg;
        dst_idx++;

        /*
         * Boundary protection.
         */
        if ((dst_idx >> 1) >= LSDB_MAX_NODE_ID_SIZE) {
            break;
        }
    }
}

char *
lsdb_format_node_id(unsigned char *node_id)
{
    static char buffer[4][32];
    static int idx = 0;
    char *ret;

    ret = buffer[idx];
    idx = (idx + 1) & 3;

    snprintf(ret, 32, "%02x%02x.%02x%02x.%02x%02x.%02x",
	     *node_id, *(node_id + 1), *(node_id + 2), *(node_id + 3),
	     *(node_id + 4), *(node_id + 5), *(node_id + 6));

    return ret;
}

char *
lsdb_format_link(lsdb_link_t *link)
{
    struct lsdb_ctx_ *ctx;
    struct lsdb_node_ *node, *remote_node;
    struct lsdb_node_ node_template;
    static char buffer[128];
    char zero_link_id[LSDB_MAX_LINK_ID_SIZE];
    int idx;
    void **p;

    node = link->node;
    ctx = node->ctx;

    /*
     * Locate the remote node.
     */
    memset(&node_template, 0, sizeof(node_template));
    memcpy(node_template.key.node_id, link->key.remote_node_id, LSDB_MAX_NODE_ID_SIZE);
    p = dict_search(ctx->node_dict, &node_template.key);
    if (p) {
        remote_node = *p;
    } else {
        remote_node = NULL;
    }

    if (ctx->protocol_id == PROTO_ISIS) {
        if (node->node_name) {
            idx = snprintf(buffer, sizeof(buffer), "%s", node->node_name);
        } else {
            idx = snprintf(buffer, sizeof(buffer), "%s", lsdb_format_node_id(node->key.node_id));
        }

        if (remote_node && remote_node->node_name) {
            idx += snprintf(buffer + idx, sizeof(buffer) - idx, " -> %s", remote_node->node_name);
        } else {
            idx += snprintf(buffer + idx, sizeof(buffer) - idx, " -> %s",
            lsdb_format_node_id(link->key.remote_node_id));
        }
    } else if (ctx->protocol_id == PROTO_OSPF2) {
        if (node->node_name) {
            idx = snprintf(buffer, sizeof(buffer), "%s", node->node_name);
        } else {
            idx = snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
            node->key.node_id[0], node->key.node_id[1], node->key.node_id[2], node->key.node_id[3]);
        }

        if (remote_node && remote_node->node_name) {
            idx = snprintf(buffer + idx, sizeof(buffer) - idx, " -> %s", node->node_name);
        } else {
            idx = snprintf(buffer + idx, sizeof(buffer) - idx, " -> %u.%u.%u.%u",
            link->key.remote_node_id[0], link->key.remote_node_id[1],
            link->key.remote_node_id[2], link->key.remote_node_id[3]);
        }
    } else {
        idx = snprintf(buffer, sizeof(buffer), "0x%08x%08x", ntohl(node->key.node_id[0]), ntohl(node->key.node_id[4]));
    }

    /*
     * Optionally print the local & remote IDs.
     */
    memset(zero_link_id, 0, sizeof(zero_link_id));
    if (memcmp(link->key.local_link_id, zero_link_id, LSDB_MAX_LINK_ID_SIZE) != 0) {
        idx += snprintf(buffer + idx, sizeof(buffer) - idx,
        ", local-id 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        link->key.local_link_id[0], link->key.local_link_id[1],
        link->key.local_link_id[2], link->key.local_link_id[3],
        link->key.local_link_id[4], link->key.local_link_id[5],
        link->key.local_link_id[6], link->key.local_link_id[7],
        link->key.local_link_id[8], link->key.local_link_id[9],
        link->key.local_link_id[10], link->key.local_link_id[11],
        link->key.local_link_id[12], link->key.local_link_id[13],
        link->key.local_link_id[14], link->key.local_link_id[15]);
    }

    if (memcmp(link->key.remote_link_id, zero_link_id, LSDB_MAX_LINK_ID_SIZE) != 0) {
        idx += snprintf(buffer + idx, sizeof(buffer) - idx,
        ", remote-id 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        link->key.remote_link_id[0], link->key.remote_link_id[1],
        link->key.remote_link_id[2], link->key.remote_link_id[3],
        link->key.remote_link_id[4], link->key.remote_link_id[5],
        link->key.remote_link_id[6], link->key.remote_link_id[7],
        link->key.remote_link_id[8], link->key.remote_link_id[9],
        link->key.remote_link_id[10], link->key.remote_link_id[11],
        link->key.remote_link_id[12], link->key.remote_link_id[13],
        link->key.remote_link_id[14], link->key.remote_link_id[15]);
    }

    return buffer;
}

char *
lsdb_format_node(lsdb_node_t *node)
{
    struct lsdb_ctx_ *ctx;
    static char buffer[64];

    ctx = node->ctx;

    if (ctx->protocol_id == PROTO_ISIS) {
        if (node->node_name) {
            snprintf(buffer, sizeof(buffer), "%s", node->node_name);
        } else {
            snprintf(buffer, sizeof(buffer), "%s", lsdb_format_node_id(node->key.node_id));
        }
    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
        if (node->node_name) {
            snprintf(buffer, sizeof(buffer), "%s", node->node_name);
        } else {
            snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
            node->key.node_id[0], node->key.node_id[1], node->key.node_id[2], node->key.node_id[3]);
        }
    } else {
        snprintf(buffer, sizeof(buffer), "0x%08x%08x", ntohl(node->key.node_id[0]), ntohl(node->key.node_id[4]));
    }

    return buffer;
}

/*
 * Format a node without substituting it by a hostname that may be set.
 */
char *
lsdb_format_node_no_name(lsdb_node_t *node)
{
    struct lsdb_ctx_ *ctx;
    static char buffer[64];

    ctx = node->ctx;

    if (ctx->protocol_id == PROTO_ISIS) {
	snprintf(buffer, sizeof(buffer), "%s", lsdb_format_node_id(node->key.node_id));
    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
		 node->key.node_id[0], node->key.node_id[1],
		 node->key.node_id[2], node->key.node_id[3]);
    } else {
        snprintf(buffer, sizeof(buffer), "0x%08x%08x",
		 ntohl(node->key.node_id[0]),
		 ntohl(node->key.node_id[4]));
    }

    return buffer;
}

/*
 * Called by dict destructor.
 */
void
lsdb_free_node(void *key, void *datum)
{
    struct lsdb_node_ *node;

    UNUSED(key);

    node = (struct lsdb_node_ *)datum;

    if (node->node_name) {
        free(node->node_name);
    }

    if (node->attr_dict) {
        dict_free(node->attr_dict, lsdb_free_attr);
        node->attr_dict = NULL;
    }

    if (node->packet_dict) {
        dict_free(node->packet_dict, lsdb_free_packet);
        node->packet_dict = NULL;
    }

    node->ctx->nodecount--;
    free(datum);
}

/*
 * Called by dict destructor.
 */
void
lsdb_free_link(void *key, void *datum)
{
    struct lsdb_link_ *link;

    UNUSED(key);

    link = (struct lsdb_link_ *)datum;

    link->node->linkcount--;
    link->node->ctx->linkcount--;

    free(datum);
}

/*
 * FNV-1a hash function.
 */
unsigned int
lsdb_hash_node(const void* k)
{
    const uint32_t *pos = (const uint32_t *)k;
    const uint32_t m = 16777619U;

    uint32_t h = 2166136261U;

    /* 64-bit node_id */
    h ^= *pos++;
    h *= m;
    h ^= *pos++;
    h *= m;

    return h;
}

/*
 * FNV-1a hash function with 64 to 32 Bit XOR diffusion at the end.
 */
unsigned int
lsdb_hash_link(const void* k)
{
    const uint64_t *pos = (const uint64_t *)k;
    const uint64_t m = 0x100000001B3ULL;

    uint64_t h = 0xcbf29ce484222325ULL;

    h ^= *pos++; /* 64-bit local_node_id */
    h *= m;

    h ^= *pos++; /* 64-bit remote_node_id */
    h *= m;

    h ^= *pos++; /* 128-bit local_link_id */
    h *= m;
    h ^= *pos++;
    h *= m;

    h ^= *pos++; /* 128-bit remote_link_id */
    h *= m;
    h ^= *pos++;
    h *= m;

    return (h >> 32) ^ h;
}

/*
 * Called by dict destructor.
 */
void
lsdb_free_packet(__attribute__((unused))void *key, void *datum)
{
    struct lsdb_ctx_ *ctx;
    struct lsdb_packet_ *packet;

    packet = (struct lsdb_packet_ *)datum;
    ctx = packet->parent->ctx;

    if (packet->on_change_list) {
        CIRCLEQ_REMOVE(&ctx->packet_change_qhead, packet, packet_change_qnode);
        ctx->ctrl_stats.packets_queued--;
    }

    free(datum);
}

/*
 * Called by dict destructor.
 */
void
lsdb_free_attr(__attribute__((unused))void *key, void *datum)
{
    free(datum);
}

int
lsdb_compare_node(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof((struct lsdb_node_ *) 0)->key);
}

int
lsdb_compare_link(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof((struct lsdb_link_ *) 0)->key);
}

int
lsdb_compare_attr(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof((struct lsdb_attr_ *) 0)->key);
}

int
lsdb_compare_packet(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof((struct lsdb_packet_ *) 0)->key);
}


struct lsdb_ctx_ *
lsdb_alloc_ctx(char *instance)
{
    struct lsdb_ctx_ *ctx;

    ctx = calloc(1, sizeof(struct lsdb_ctx_));
    if (!ctx) {
       return NULL;
    }

    /*
     * Clone names.
     */
    if (instance) {
        ctx->instance_name = strdup(instance);
    }

    /*
     * Initialize node DB.
     */
    ctx->node_dict = hashtable2_dict_new((dict_compare_func)lsdb_compare_node,
					 lsdb_hash_node, LSDB_NODE_HSIZE);

    /*
     * Initialize link DB.
     */
    ctx->link_dict = hashtable2_dict_new((dict_compare_func)lsdb_compare_link,
					 lsdb_hash_link, LSDB_LINK_HSIZE);

    LOG(NORMAL, "Add context for instance %s\n", ctx->instance_name);

    return ctx;
}

/*
 * Delete a link from the database.
 */
void
lsdb_delete_link(struct lsdb_ctx_ *ctx, struct lsdb_link_ *link_template)
{
    struct lsdb_link_ *link;
    void **p;

    p = dict_search(ctx->link_dict, &link_template->key);
    if (!p) {
        return;
    }
    link = *p;

    /*
     * Remove any inverse links that we may have.
     */
    if (link->inverse_link) {
        link->inverse_link->inverse_link = NULL;
    }

    /*
     * Unlink and free.
     */
    CIRCLEQ_REMOVE(&link->node->link_qhead, link, link_qnode);
    dict_remove(ctx->link_dict, &link_template->key);
    free(link);
}

/*
 * Delete a node and all of its outgoing links in the database.
 */
void
lsdb_delete_node(struct lsdb_ctx_ *ctx, struct lsdb_node_ *node_template)
{
    struct lsdb_node_ *node;
    struct lsdb_link_ *link;
    void **p;

    /*
     * First locate the node.
     */
    p = dict_search(ctx->node_dict, &node_template->key);
    if (!p) {
        return;
    }
    node = *p;

    /*
     * Delete the links in a safe manner.
     */
    while (!CIRCLEQ_EMPTY(&node->link_qhead)) {
        link = CIRCLEQ_FIRST(&node->link_qhead);
        lsdb_delete_link(ctx, link);
    }

    /*
     * Stop refresh timer.
     */
    timer_del(node->refresh_timer);
    node->refresh_timer->ptimer = NULL; /* Reset field such that timer library does not late ref */

    dict_remove(ctx->node_dict, &node_template->key);
    free(node);
}

/*
 * First search a node in the database before adding.
 * Create if not exists.
 */
struct lsdb_node_ *
lsdb_add_node(struct lsdb_ctx_ *ctx, struct lsdb_node_ *node_template)
{
    struct lsdb_node_ *node;
    dict_insert_result result;
    void **p;

    p = dict_search(ctx->node_dict, &node_template->key);
    if (!p) {
        /*
         * Create a fresh node.
         */
        node = calloc(1, sizeof(struct lsdb_node_));
        if (!node) {
            return NULL;
        }

        /*
         * Copy key.
         */
        memcpy(&node->key, &node_template->key, sizeof(node->key));
        if (node_template->node_name) {
            node->node_name = strdup(node_template->node_name);
        }

        /*
         * Init head for links hanging off this node.
         */
        CIRCLEQ_INIT(&node->link_qhead);

        /*
         * Assign a monotonically index for mapping loopback IPs and system-ID.
         */
        node->node_index = ctx->node_index;
        ctx->node_index++;

        /*
         * Insert node into node dictionary hanging off a context.
         */
        result = dict_insert(ctx->node_dict, &node->key);
        if (!result.inserted) {
            return NULL;
        }
        *result.datum_ptr = node;

        /*
         * Book keeping.
         */
        ctx->nodecount++;
        node->ctx = ctx;

	/*
	 * Default sequence number to inherit from context.
	 */
	node->sequence = ctx->sequence;

        LOG(LSDB, "  Add node %s (%s) node-ptr %p\n", lsdb_format_node(node),
            lsdb_format_node_id(node->key.node_id), (void *)node);

        return node;
    }

    return *p;
}

/*
 * Search a node in the database.
 */
lsdb_node_t *
lsdb_get_node(struct lsdb_ctx_ *ctx, lsdb_node_t *node_template)
{
    void **p;

    p = dict_search(ctx->node_dict, &node_template->key);
    if (!p) {
        return NULL;
    }
    return *p;
}

/*
 * Try to find the inverse link of a given link.
 */
lsdb_link_t *
lsdb_find_inverse_link(struct lsdb_ctx_ *ctx, struct lsdb_link_ *link)
{
    struct lsdb_link_ link_template;
    void **p;

    /*
     * Reverse the local and remote portions of the link key.
     */
    memset(&link_template, 0, sizeof(link_template));
    memcpy(&link_template.key.local_node_id, link->key.remote_node_id, LSDB_MAX_NODE_ID_SIZE);
    memcpy(&link_template.key.remote_node_id, link->key.local_node_id, LSDB_MAX_NODE_ID_SIZE);
    memcpy(&link_template.key.local_link_id, link->key.remote_link_id, LSDB_MAX_LINK_ID_SIZE);
    memcpy(&link_template.key.remote_link_id, link->key.local_link_id, LSDB_MAX_LINK_ID_SIZE);

    p = dict_search(ctx->link_dict, &link_template.key);
    if (!p) {
        return NULL;
    }
    return *p;
}

/*
 * First search a link in the database before adding.
 * Create if not exists.
 */
struct lsdb_link_ *
lsdb_add_link(struct lsdb_ctx_ *ctx, struct lsdb_node_ *node, struct lsdb_link_ *link_template)
{
    struct lsdb_link_ *link, *inverse_link;
    dict_insert_result result;
    void **p;

    p = dict_search(ctx->link_dict, &link_template->key);
    if (!p) {
        /*
         * Create a fresh link.
         */
        link = calloc(1, sizeof(struct lsdb_link_));
        if (!link) {
            return NULL;
        }

        /*
         * Copy the key and metric in one shot.
         */
        memcpy(link, link_template, sizeof(struct lsdb_link_));

        /*
         * Insert link into link dictionary hanging off a context.
         */
        result = dict_insert(ctx->link_dict, &link->key);
        if (!result.inserted) {
            return NULL;
        }
        *result.datum_ptr = link;

        /*
         * Add link to the linked list hanging off this node.
         */
        CIRCLEQ_INSERT_TAIL(&node->link_qhead, link, link_qnode);

        /*
         * Book keeping.
         */
        ctx->linkcount++;
        node->linkcount++;
        link->node = node;

        LOG(LSDB, "  Add link %s, metric %u\n", lsdb_format_link(link), link->link_metric);

        /*
         * Try to find the inverse link and store it.
         * That makes the 2-way check during Dijkstra calculation a O(1) operation.
         */
        inverse_link = lsdb_find_inverse_link(ctx, link);
        if (inverse_link) {
            LOG(LSDB, "    Inverse link %s found\n", lsdb_format_link(inverse_link));

            /*
             * Connect the link and inverse link mutually.
             */
            link->inverse_link = inverse_link;
            inverse_link->inverse_link = link;

	    /*
	     * Inherit the link index from the inverse link,
	     * such that the same prefix is assigned to both links.
	     */
	    if (inverse_link->link_index) {
		link->link_index = inverse_link->link_index;
	    }

	    return link;
	}

        /*
         * Assign a monotonically index for mapping links IPs.
         */
        link->link_index = ctx->link_index;
        ctx->link_index++;

        return link;
    }

    return *p;
}

/*
 * Get SPF Link.
 */
struct lsdb_link_ *
lsdb_get_link(struct lsdb_ctx_ *ctx, struct lsdb_link_ *link_template)
{
    void **p;

    p = dict_search(ctx->link_dict, &link_template->key);
    if (!p) {
        return NULL;
    }
    return *p;
}

/*
 * Link State Attributes / name mappings
 */
struct keyval_ attr_names[] = {
    { ISIS_TLV_AREA, "Area" },
    { ISIS_TLV_PROTOCOLS, "Protocol" },
    { ISIS_TLV_EXTD_IS_REACH, "Link" },
    { ISIS_TLV_IPV4_ADDR, "IPv4 Address" },
    { ISIS_TLV_IPV6_ADDR, "IPv6 Address" },
    { ISIS_TLV_EXTD_IPV4_REACH, "IPv4 Prefix" },
    { ISIS_TLV_EXTD_IPV6_REACH, "IPv6 Prefix" },
    { ISIS_TLV_HOSTNAME, "Hostname" },
    { ISIS_TLV_CAP, "Capability" },
    { 0, NULL}
};

char *
lsdb_format_attr(struct lsdb_attr_ *attr)
{
    static char buf[128];
    int len;

    len = snprintf(buf, sizeof(buf), "%s (%u)", val2key(attr_names, attr->key.attr_type), attr->key.attr_type);

    switch(attr->key.attr_type) {
        case ISIS_TLV_PROTOCOLS:
            len += snprintf(buf+len, sizeof(buf)-len, " 0x%x", attr->key.protocol);
            break;
        case ISIS_TLV_EXTD_IS_REACH:
            len += snprintf(buf+len, sizeof(buf)-len, " %s, metric %u",
                    lsdb_format_node_id(attr->key.link.remote_node_id),
                    attr->key.link.metric);
            break;
        case ISIS_TLV_IPV4_ADDR:
            len += snprintf(buf+len, sizeof(buf)-len, " %s",
                    format_ipv4_address((uint32_t*)attr->key.ipv4_addr));
            break;
        case ISIS_TLV_IPV6_ADDR:
            len += snprintf(buf+len, sizeof(buf)-len, " %s",
                    format_ipv6_address((ipv6addr_t*)attr->key.ipv6_addr));
            break;
        case ISIS_TLV_EXTD_IPV4_REACH:
            len += snprintf(buf+len, sizeof(buf)-len, " %s, metric %u",
                    format_ipv4_prefix(&attr->key.prefix.ipv4_prefix),
                    attr->key.prefix.metric);
            break;
        case ISIS_TLV_EXTD_IPV6_REACH:
            len += snprintf(buf+len, sizeof(buf)-len, " %s, metric %u",
                    format_ipv6_prefix(&attr->key.prefix.ipv6_prefix),
                    attr->key.prefix.metric);
            break;
        case ISIS_TLV_HOSTNAME:
            len += snprintf(buf+len, sizeof(buf)-len, " '%s'", attr->key.hostname);
            break;
        default:
            break;
    }
    return buf;
}

/*
 * Use this function to clear attributes.
 * The default ordinal is set to the worst.
 * By changing the ordinal before insertion desired  attributes will be generated first.
 */
void
lsdb_reset_attr_template(lsdb_attr_t *attr_template)
{
    memset(attr_template, 0, sizeof(struct lsdb_attr_));
    attr_template->key.ordinal = 255; /* worst ordering position */
}

bool
lsdb_is_ipv4_attr(lsdb_attr_t *attr)
{
    switch (attr->key.attr_type) {
        case ISIS_TLV_IPV4_ADDR:
        case ISIS_TLV_EXTD_IPV4_REACH:
            return true;
        case ISIS_TLV_PROTOCOLS:
            if (attr->key.protocol == NLPID_IPV4) {
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

bool
lsdb_is_ipv6_attr(lsdb_attr_t *attr)
{
    switch (attr->key.attr_type) {
        case ISIS_TLV_IPV6_ADDR:
        case ISIS_TLV_EXTD_IPV6_REACH:
            return true;
        case ISIS_TLV_PROTOCOLS:
            if (attr->key.protocol == NLPID_IPV6) {
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

/*
 * First search a node attr in the database before adding.
 * Create if not exists.
 */
lsdb_attr_t *
lsdb_add_node_attr(lsdb_node_t *node, lsdb_attr_t *attr_template)
{
    dict_insert_result result;
    struct lsdb_attr_ *attr;
    void **p;
    uint8_t data[255]; /* One max-sized TLV */
    struct io_buffer_ buf;

    if (!node) {
        return NULL;
    }

    /*
     * Refuse addition of v4 attributes if v4 is turned off.
     */
    if (node->ctx->no_ipv4 && lsdb_is_ipv4_attr(attr_template)) {
        return NULL;
    }

    /*
     * Refuse addition of v6 attributes if v6 is turned off.
     */
    if (node->ctx->no_ipv6 && lsdb_is_ipv6_attr(attr_template)) {
        return NULL;
    }

    /*
     * Init the attribute dict on first insertion.
     */
    if (!node->attr_dict) {
        node->attr_dict = hb_dict_new((dict_compare_func)lsdb_compare_attr);
    }

    p = dict_search(node->attr_dict, &attr_template->key);
    if (!p) {
        /*
         * Create a fresh attribute.
         */
        attr = calloc(1, sizeof(struct lsdb_attr_));
        if (!attr) {
            return NULL;
        }

        /*
         * Copy key.
         */
        memcpy(&attr->key, &attr_template->key, sizeof(attr->key));

        /*
         * Insert attribute into attr dictionary hanging off a node.
         */
        result = dict_insert(node->attr_dict, &attr->key);
        if (!result.inserted) {
            return NULL;
        }
        *result.datum_ptr = attr;

        /*
         * Calculate the size, by serializing the data into a dummy buffer.
         */
        buf.data = data;
        buf.idx = 0;
        buf.size = sizeof(data);
        lspgen_serialize_attr(attr, &buf);
        attr->size = buf.idx;

        /*
         * Book keeping.
         */
        node->attr_count++;

        LOG(LSDB, "  Add attr %s to node %s (%s), size %u\n",
            lsdb_format_attr(attr),
            lsdb_format_node(node),
            lsdb_format_node_id(node->key.node_id),
            attr->size);

        return attr;
    }
    return *p;
}

/*
 * Safeley free a name.
 */
void
lsdb_free_name (char **name_ptr)
{
    char *name;

    name = *name_ptr;
    if (!name) {
        return;
    }

    free(name);
    *name_ptr = NULL;
}

/*
 * Destroy a context.
 */
void
lsdb_delete_ctx(struct lsdb_ctx_ *ctx)
{

    timer_flush_root(&ctx->timer_root);

    dict_free(ctx->link_dict, lsdb_free_link);
    ctx->link_dict = NULL;
    dict_free(ctx->node_dict, lsdb_free_node);
    ctx->node_dict = NULL;

    lsdb_free_name(&ctx->instance_name);
    lsdb_free_name(&ctx->graphviz_filename);
    lsdb_free_name(&ctx->pcap_filename);
    lsdb_free_name(&ctx->mrt_filename);
    lsdb_free_name(&ctx->stream_filename);
    lsdb_free_name(&ctx->config_filename);
    lsdb_free_name(&ctx->ctrl_socket_path);
    lsdb_free_name(&ctx->authentication_key);

    if (ctx->ctrl_io_buf.data) {
        free(ctx->ctrl_io_buf.data);
        ctx->ctrl_io_buf.data = NULL;
    }

    if (ctx->ctrl_socket_sockfd > 0) {
	 close(ctx->ctrl_socket_sockfd);
	 ctx->ctrl_socket_sockfd = 0;
     }

    free(ctx);
}

void
lsdb_dump_graphviz(lsdb_ctx_t *ctx)
{
    FILE *graphviz;
    char filename[256];
    struct lsdb_node_ *node, *root;
    struct lsdb_link_ *link;
    dict_itor *itor;
    unsigned int nodes;
    void **p;

    if (!ctx->graphviz_filename) {
        LOG_NOARG(ERROR, "No graphviz filename specified.\n");
        return;
    }

    snprintf(filename, sizeof(filename), "%s.dot", ctx->graphviz_filename);
    graphviz = fopen(filename, "w");
    if (!graphviz) {
        LOG(ERROR, "Error opening graphviz file %s\n", filename);
        return;
    }

    /*
     * Walk the node DB.
     */
    itor = dict_itor_new(ctx->node_dict);
    if (!itor) {
        return;
    }

    /*
     * Node DB empty ?
     */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG_NOARG(ERROR, "Empty LSDB.\n");
        return;
    }

    fprintf(graphviz, "digraph \"%s.%s\" {\n", ctx->instance_name, lsdb_format_proto(ctx));

    /*
     * First lookup the root node.
     * Graphviz renders the graphs much more nicer
     * if the root node and its neighbors get listed first.
     */
    nodes = 0;
    p = dict_search(ctx->node_dict, ctx->root_node_id);
    if (!p) {
        root = NULL;
    } else {
        root = *p;
    }

    if (root) {
        fprintf(graphviz, "  \"%s\" [label=\"%s\\nroot\",style=filled];\n",
                lsdb_format_node_id(root->key.node_id), lsdb_format_node(root));
        CIRCLEQ_FOREACH(link, &root->link_qhead, link_qnode) {
            fprintf(graphviz, "    \"%s\" -> \"%s\" [label=\"%u\"];\n",
            lsdb_format_node_id(link->key.local_node_id),
            lsdb_format_node_id(link->key.remote_node_id), link->link_metric);
        }
        nodes++;
    }

    do {
        node = *dict_itor_datum(itor);

        /*
        * The root node was already printed.
        */
        if (node == root) {
            continue;
        }

        fprintf(graphviz, "  \"%s\" [label=\"%s\"];\n", lsdb_format_node_id(node->key.node_id), lsdb_format_node(node));

        /*
         * Walk all of our neighbors.
         */
        CIRCLEQ_FOREACH(link, &node->link_qhead, link_qnode) {
            fprintf(graphviz, "    \"%s\" -> \"%s\" [label=\"%u\"];\n",
            lsdb_format_node_id(link->key.local_node_id),
            lsdb_format_node_id(link->key.remote_node_id), link->link_metric);
        }
        nodes++;

    } while (dict_itor_next(itor));
    dict_itor_free(itor);
    fprintf(graphviz, "}\n");
    fclose(graphviz);
    LOG(NORMAL, "Wrote %u nodes into graphviz file %s\n", nodes, filename);
}
