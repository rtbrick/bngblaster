/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */
#include <signal.h>

#include "libdict/dict.h"

#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"
#include "lspgen_ospf.h"

/*
 * Globals
 */
bool loop_running = true;

/*
 * Prototypes
 */
const char banner[] = "\n"
"      ____   __   ____         _        __            ,/\n"
"     / __ \\ / /_ / __ ) _____ (_)_____ / /__        ,'/\n"
"    / /_/ // __// __  |/ ___// // ___// //_/      ,' /\n"
"   / _, _// /_ / /_/ // /   / // /__ / ,<       ,'  /_____,    \n"
"  /_/ |_| \\__//_____//_/   /_/ \\___//_/|_|    .'____    ,'   \n"
"      __   _____ ____  ______                      /  ,'\n"
"     / /  / ___// __ \\/ ____/__  ____             / ,'\n"
"    / /   \\__ \\/ /_/ / / __/ _ \\/ __ \\           /,'\n"
"   / /______/ / ____/ /_/ /  __/ / / /          / \n"
"  /_____/____/_/    \\____/\\___/_/ /_/\n\n";

/*
 * Command line options.
 */
static struct option long_options[] = {
    {"version", no_argument, NULL, 'v'},
    {"area", required_argument, NULL, 'a'},
    {"protocol", required_argument, NULL, 'P'},
    {"authentication-key", required_argument, NULL, 'K'},
    {"authentication-type", required_argument, NULL, 'T'},
    {"read-config-file", required_argument, NULL, 'r'},
    {"write-config-file", required_argument, NULL, 'w'},
    {"connector", required_argument, NULL, 'C'},
    {"control-socket", required_argument, NULL, 'S'},
    {"ipv4-link-prefix", required_argument, NULL, 'l'},
    {"ipv6-link-prefix", required_argument, NULL, 'L'},
    {"ipv4-node-prefix", required_argument, NULL, 'n'},
    {"ipv6-node-prefix", required_argument, NULL, 'N'},
    {"ipv4-external-prefix", required_argument, NULL, 'x'},
    {"ipv6-external-prefix", required_argument, NULL, 'X'},
    {"lsp-lifetime", required_argument, NULL, 'M'},
    {"no-ipv4", no_argument, NULL, 'z'},
    {"no-ipv6", no_argument, NULL, 'Z'},
    {"no-sr", no_argument, NULL, 'y'},
    {"external-count", required_argument, NULL, 'e'},
    {"graphviz-file", required_argument, NULL, 'g'},
    {"help", no_argument, NULL, 'h'},
    {"mrt-file", required_argument, NULL, 'm'},
    {"node-count", required_argument, NULL, 'c'},
    {"pcap-file", required_argument, NULL, 'p'},
    {"purge", no_argument, NULL, 'G'},
    {"stream-file", required_argument, NULL, 'f'},
    {"seed", required_argument, NULL, 's'},
    {"sequence", required_argument, NULL, 'q'},
    {"quit-loop", no_argument, NULL, 'Q'},
    {"level", required_argument, NULL, 'V'},
    {"log", required_argument,  NULL, 't' },
    {NULL, 0, NULL, 0}
};

/*
 * Log target / name translation table.
 */
struct keyval_ log_names[] = {
    { NORMAL,        "normal" },
    { DEBUG,         "debug" },
    { LSP,           "lsp" },
    { LSDB,          "lsdb" },
    { PACKET,        "packet" },
    { CTRL,          "ctrl" },
    { ERROR,         "error" },
#ifdef BNGBLASTER_TIMER_LOGGING
    { TIMER,         "timer" },
    { TIMER_DETAIL,  "timer-detail" },
#endif
    { 0, NULL}
};

/*
 * Protocool / name translation table.
 */
struct keyval_ proto_names[] = {
    { PROTO_ISIS, "isis" },
    { PROTO_OSPF2, "ospf2" },
    { PROTO_OSPF3, "ospf3" },
    { 0, NULL}
};

const char *
lsdb_format_proto (struct lsdb_ctx_ *ctx)
{
    return val2key(proto_names, ctx->protocol_id);
}

/*
 * IS-IS authentication type / name translation table.
 */
struct keyval_ isis_auth_names[] = {
    { ISIS_AUTH_NONE, "none" },
    { ISIS_AUTH_SIMPLE, "simple" },
    { ISIS_AUTH_MD5, "md5" },
    { 0, NULL}
};

char *
lspgen_print_usage_arg(struct option *option)
{
    static char buf[128];
    struct keyval_ *ptr;
    int len;

    if (option->has_arg == 1) {

	/* protocol */
	if (strcmp(option->name, "protocol") == 0) {
            len = 0;
            ptr = proto_names;
            while (ptr->key) {
                len += snprintf(buf+len, sizeof(buf)-len, "%s%s", len ? "|" : " ", ptr->key);
                ptr++;
            }
            return buf;
        }

	/* logging */
	if (strcmp(option->name, "log") == 0) {
            len = 0;
            ptr = log_names;
            while (ptr->key) {
                len += snprintf(buf+len, sizeof(buf)-len, "%s%s", len ? "|" : " ", ptr->key);
                ptr++;
            }
            return buf;
        }

	/* authentication-type */
        if (strcmp(option->name, "authentication-type") == 0) {
            len = 0;
            ptr = isis_auth_names;
            while (ptr->key) {
                len += snprintf(buf+len, sizeof(buf)-len, "%s%s", len ? "|" : " ", ptr->key);
                ptr++;
            }
            return buf;
        }
        return " <args>";
    }
    return "";
}

static void
lspgen_print_version(void)
{
    if(sizeof(BNGBLASTER_VERSION)-1) {
        printf("Version: %s\n", BNGBLASTER_VERSION);
    }
    if(sizeof(GIT_REF)-1 + sizeof(GIT_SHA)-1) {
        printf("GIT:\n");
        printf("  REF: %s\n", GIT_REF);
        printf("  SHA: %s\n", GIT_SHA);
    }
}

void
lspgen_print_usage(void)
{
    uint16_t idx;

    printf("%s", banner);
    printf("Usage: lspgen [OPTIONS]\n\n");

    for (idx = 0;; idx++) {
        if (!long_options[idx].name) {
            break;
        }
        printf("  -%c --%s%s\n", long_options[idx].val, long_options[idx].name,
               lspgen_print_usage_arg(&long_options[idx]));
    }
}

/*
 * Map the authentication type
 */
uint32_t
get_authentication_type(char *auth_type_name)
{
    int idx;

    idx = 0;
    while (isis_auth_names[idx].key) {
        if (strcmp(isis_auth_names[idx].key, auth_type_name) == 0) {
            return isis_auth_names[idx].val;
        }
        idx++;
    }
    return ISIS_AUTH_NONE;
}

__uint128_t
lspgen_load_addr(uint8_t *buf, uint32_t len)
{
    __uint128_t addr;
    uint32_t idx;

    addr = *buf;
    for (idx = 1; idx < len; idx++) {
        addr = addr << 8;
        addr |= buf[idx];
    }

    return addr;
}

void
lspgen_store_addr(__uint128_t addr, uint8_t *buf, uint32_t len)
{
    uint32_t idx;

    for (idx = len; idx; idx--) {
        buf[idx-1] = addr & 0xff;
        addr = addr >> 8;
    }
}

/*
 * Drain the stack of nibbles.
 */
void
lspgen_drain_nibble_stack(uint8_t *stack, uint32_t *stack_idx, uint8_t **end_buf_ptr)
{
    uint32_t idx;

    if (*stack_idx < 2) {
        return;
    }

    idx = 0;
    while ((*stack_idx - idx) >= 2) {
        **end_buf_ptr = stack[idx] + (stack[idx+1] << 4);
        *end_buf_ptr -= 1;
        idx += 2;
    }

    /*
     * Rebase Stack.
     */
    stack[0] = stack[idx];
    *stack_idx -= idx;
}

void
lspgen_store_bcd_addr(__uint128_t addr, uint8_t *buf, uint32_t len)
{
    uint32_t idx, stack_idx, digit;
    uint8_t bcd_digit[3];
    uint8_t stack[4];
    uint8_t *end_buf;

    /* Length must only be multiple of two */
    if (len % 2) {
        return;
    }

    /*
     * BCD strings consume 50% more space and written from tail to head
     */
    end_buf = buf + ((len*3)/2)-1;
    stack_idx = 0;
    for (idx = 0; idx < len; idx++) {
        /*
         * Load a byte and do the decimal conversation.
         */
        digit = addr & 0xff;
        bcd_digit[0] = digit/100;
        digit -= bcd_digit[0] * 100;
        bcd_digit[1] = digit/10;
        digit -= bcd_digit[1] * 10;
        bcd_digit[2] = digit;

        /*
         * Now push the nibbles to the stack.
         */
        stack[stack_idx++] = bcd_digit[2];
        stack[stack_idx++] = bcd_digit[1];
        stack[stack_idx++] = bcd_digit[0];

        lspgen_drain_nibble_stack(stack, &stack_idx, &end_buf);
        addr = addr >> 8;
    }
}

/*
 * Calculate the prefix increment length depending on the prefix length
 */
__uint128_t
lspgen_get_prefix_inc(uint32_t afi, uint32_t prefix_len)
{
    __uint128_t prefix_inc;
    uint32_t inc_bit;

    prefix_inc = 0;
    switch(afi) {
        case AF_INET:
            prefix_inc = 1L << (32 - prefix_len);
            break;
        case AF_INET6:
            /* We have to do this madness below to overcome the fact
             * That the gcc code generated from shifting uint128 is not
             * what is expected. */
            inc_bit = 128 - prefix_len;
            prefix_inc = 1L;
            while (inc_bit > 32) {
                prefix_inc = prefix_inc << 32;
                inc_bit -= 32;
            }
            prefix_inc = prefix_inc << inc_bit;
            break;
        default:
            break;
    }
    return prefix_inc;
}

/*
 * Walk the graph of the LSDB and add the required node/link attributes for IS-IS LSP generation.
 */
void
lspgen_gen_isis_attr(struct lsdb_ctx_ *ctx)
{
    struct lsdb_node_ *node;
    struct lsdb_link_ *link;
    struct lsdb_attr_ attr_template;
    dict_itor *itor;
    __uint128_t addr, inc, ext_addr4, ext_incr4, ext_addr6, ext_incr6;
    uint32_t ext_per_node, idx, nodes_left, ext_left;

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

    /*
     * For external routes load the first address of the pool.
     */
    ext_addr4 = lspgen_load_addr((uint8_t*)&ctx->ipv4_ext_prefix.address, sizeof(ipv4addr_t));
    ext_incr4 = lspgen_get_prefix_inc(AF_INET, ctx->ipv4_ext_prefix.len);
    ext_addr6 = lspgen_load_addr((uint8_t*)&ctx->ipv6_ext_prefix.address, IPV6_ADDR_LEN);
    ext_incr6 = lspgen_get_prefix_inc(AF_INET6, ctx->ipv6_ext_prefix.len);

    nodes_left = ctx->num_nodes;
    ext_left = ctx->num_ext;

    do {
        node = *dict_itor_datum(itor);

        /* Area */
        for (idx = 0; idx < ctx->num_area; idx++) {
            lsdb_reset_attr_template(&attr_template);
            memcpy(&attr_template.key.area, &ctx->area[idx], sizeof(attr_template.key.area));
            attr_template.key.ordinal = 1;
            attr_template.key.attr_type = ISIS_TLV_AREA;
            lsdb_add_node_attr(node, &attr_template);
        }

        /* Protocols */
        lsdb_reset_attr_template(&attr_template);
        attr_template.key.ordinal = 1;
        attr_template.key.protocol = NLPID_IPV4; /* ipv4 */
        attr_template.key.attr_type = ISIS_TLV_PROTOCOLS;
        lsdb_add_node_attr(node, &attr_template);
        attr_template.key.protocol = NLPID_IPV6; /* ipv6 */
        lsdb_add_node_attr(node, &attr_template);

        /* Host name */
        if (node->node_name) {
            lsdb_reset_attr_template(&attr_template);
            attr_template.key.ordinal = 1;
            attr_template.key.attr_type = ISIS_TLV_HOSTNAME;
            strncpy(attr_template.key.hostname, node->node_name, sizeof(attr_template.key.hostname)-1);
            lsdb_add_node_attr(node, &attr_template);
        }

        /* IPv4 loopback address */
        lsdb_reset_attr_template(&attr_template);
        addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t));
        addr += node->node_index;
        lspgen_store_addr(addr, attr_template.key.ipv4_addr, sizeof(ipv4addr_t));
        attr_template.key.ordinal = 1;
        attr_template.key.attr_type = ISIS_TLV_IPV4_ADDR;
        lsdb_add_node_attr(node, &attr_template);

        /* IPv4 loopback prefix */
        lsdb_reset_attr_template(&attr_template);
        lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, sizeof(ipv4addr_t));
        attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_node_prefix.len;
        if (!ctx->no_sr) {
            attr_template.key.prefix.sid = node->node_index;
            attr_template.key.prefix.adv_sid = true;
        }
        attr_template.key.prefix.node_flag = true;
        attr_template.key.ordinal = 1;
        attr_template.key.attr_type = ISIS_TLV_EXTD_IPV4_REACH;
        lsdb_add_node_attr(node, &attr_template);

        /* IPv6 loopback address */
        lsdb_reset_attr_template(&attr_template);
        addr = lspgen_load_addr(ctx->ipv6_node_prefix.address, IPV6_ADDR_LEN);
        addr += node->node_index;
        lspgen_store_addr(addr, attr_template.key.ipv6_addr, IPV6_ADDR_LEN);
        attr_template.key.ordinal = 1;
        attr_template.key.attr_type = ISIS_TLV_IPV6_ADDR;
        lsdb_add_node_attr(node, &attr_template);

        /* IPv6 loopback prefix */
        lsdb_reset_attr_template(&attr_template);
        lspgen_store_addr(addr, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
        attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_node_prefix.len;
        if (!ctx->no_sr) {
            attr_template.key.prefix.sid = ctx->srgb_range/2 + node->node_index;
            attr_template.key.prefix.adv_sid = true;
        }
        attr_template.key.prefix.node_flag = true;
        attr_template.key.ordinal = 1;
        attr_template.key.attr_type = ISIS_TLV_EXTD_IPV6_REACH;
        lsdb_add_node_attr(node, &attr_template);

        /* external prefixes */
	ext_per_node = ext_left / nodes_left;
	ext_left -= ext_per_node;
        while (ext_per_node--) {
            /* ipv4 external prefix */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(ext_addr4, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, 4);
            attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_ext_prefix.len;
            attr_template.key.prefix.metric = 100;
            attr_template.key.attr_type = ISIS_TLV_EXTD_IPV4_REACH;
            lsdb_add_node_attr(node, &attr_template);
            ext_addr4 += ext_incr4;

            /* ipv6 external prefix */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(ext_addr6, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
            attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_ext_prefix.len;
            attr_template.key.prefix.metric = 100;
            attr_template.key.attr_type = ISIS_TLV_EXTD_IPV6_REACH;
            lsdb_add_node_attr(node, &attr_template);
            ext_addr6 += ext_incr6;
        }

        if (!ctx->no_sr) {
            /* SR capability */
            lsdb_reset_attr_template(&attr_template);
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t));
            addr += node->node_index;
            lspgen_store_addr(addr, attr_template.key.cap.router_id, sizeof(ipv4addr_t));
            attr_template.key.cap.srgb_base = ctx->srgb_base;
            attr_template.key.cap.srgb_range = ctx->srgb_range;
            if (!ctx->no_ipv4) {
                attr_template.key.cap.mpls_ipv4_flag = true; /* mpls ipv4 */
            }
            if (!ctx->no_ipv6) {
                attr_template.key.cap.mpls_ipv6_flag = true; /* mpls ipv6 */
            }
            attr_template.key.attr_type = ISIS_TLV_CAP;
            attr_template.key.ordinal = 1;
            lsdb_add_node_attr(node, &attr_template);
        }

        /*
         * Walk all of our neighbors.
         */
        CIRCLEQ_FOREACH(link, &node->link_qhead, link_qnode) {

            /* Generate an IS reach for each link */
            lsdb_reset_attr_template(&attr_template);
            attr_template.key.attr_type = ISIS_TLV_EXTD_IS_REACH;
            memcpy(attr_template.key.link.remote_node_id, link->key.remote_node_id, 7);
            attr_template.key.link.metric = link->link_metric;
            lsdb_add_node_attr(node, &attr_template);

            /* Generate an IPv4 prefix for each link */
            lsdb_reset_attr_template(&attr_template);
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_link_prefix.address, sizeof(ipv4addr_t));
            inc = lspgen_get_prefix_inc(AF_INET, ctx->ipv4_link_prefix.len);
            addr += link->link_index * inc;
            lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, sizeof(ipv4addr_t));
            attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_link_prefix.len;
            attr_template.key.prefix.metric = link->link_metric;
            attr_template.key.attr_type = ISIS_TLV_EXTD_IPV4_REACH;
            lsdb_add_node_attr(node, &attr_template);

            /* Generate an IPv6 prefix for each link */
            lsdb_reset_attr_template(&attr_template);
            addr = lspgen_load_addr(ctx->ipv6_link_prefix.address, IPV6_ADDR_LEN);
            inc = lspgen_get_prefix_inc(AF_INET6, ctx->ipv6_link_prefix.len);
            addr += link->link_index * inc;
            lspgen_store_addr(addr, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
            attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_link_prefix.len;
            attr_template.key.prefix.metric = link->link_metric;
            attr_template.key.attr_type = ISIS_TLV_EXTD_IPV6_REACH;
            lsdb_add_node_attr(node, &attr_template);
        }

	nodes_left--;
    } while (dict_itor_next(itor));

    dict_itor_free(itor);
}

/*
 * Walk the graph of the LSDB and add the required node/link attributes for OSPFv2 LSP generation.
 */
void
lspgen_gen_ospf2_attr(struct lsdb_ctx_ *ctx)
{
    struct lsdb_node_ *node;
    struct lsdb_link_ *link;
    struct lsdb_attr_ attr_template;
    dict_itor *itor;
    __uint128_t addr, inc, ext_addr4, ext_incr4, addr_offset;
    uint32_t ext_per_node, metric, nodes_left, ext_left;

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

    /*
     * For external routes load the first address of the pool.
     */
    ext_addr4 = lspgen_load_addr((uint8_t*)&ctx->ipv4_ext_prefix.address, sizeof(ipv4addr_t));
    ext_incr4 = lspgen_get_prefix_inc(AF_INET, ctx->ipv4_ext_prefix.len);

    nodes_left = ctx->num_nodes;
    ext_left = ctx->num_ext;

    do {
        node = *dict_itor_datum(itor);

        /* Host name */
        if (node->node_name) {
            lsdb_reset_attr_template(&attr_template);
            attr_template.key.ordinal = 1;
	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_RI;
            attr_template.key.attr_cp[2] = OSPF_TLV_HOSTNAME;
            strncpy(attr_template.key.hostname, node->node_name, sizeof(attr_template.key.hostname)-1);
            lsdb_add_node_attr(node, &attr_template);
        }

        /* IPv4 loopback prefix */
        lsdb_reset_attr_template(&attr_template);
        addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t));
        lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, sizeof(ipv4addr_t));
        attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_node_prefix.len;
	attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
	attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_STUB;
        lsdb_add_node_attr(node, &attr_template);

        if (!ctx->no_sr) {
	    lsdb_reset_attr_template(&attr_template);
	    lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, sizeof(ipv4addr_t));
	    attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_node_prefix.len;
	    attr_template.key.prefix.sid = node->node_index;

            attr_template.key.ordinal = 1;
	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_EP;
	    attr_template.key.attr_cp[2] = OSPF_TLV_EXTENDED_PREFIX_RANGE;
	    lsdb_add_node_attr(node, &attr_template);
	}
        addr += node->node_index;

        /* external prefixes */
	ext_per_node = ext_left / nodes_left;
	ext_left -= ext_per_node;
        while (ext_per_node--) {
            /* ipv4 external prefix */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(ext_addr4, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, 4);
            attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_ext_prefix.len;
            attr_template.key.prefix.metric = 100;

	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_EXTERNAL;
	    attr_template.key.start_tlv = true;
            lsdb_add_node_attr(node, &attr_template);
            ext_addr4 += ext_incr4;
        }

        if (!ctx->no_sr) {
            /* SR capability */
            lsdb_reset_attr_template(&attr_template);
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t));
            addr += node->node_index;
            lspgen_store_addr(addr, attr_template.key.cap.router_id, sizeof(ipv4addr_t));
            attr_template.key.cap.srgb_base = ctx->srgb_base;
            attr_template.key.cap.srgb_range = ctx->srgb_range;
	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_RI;
	    attr_template.key.attr_cp[2] = OSPF_TLV_SID_LABEL_RANGE;
	    attr_template.key.ordinal = 1;
            lsdb_add_node_attr(node, &attr_template);
        }

        /*
         * Walk all of our neighbors.
         */
        CIRCLEQ_FOREACH(link, &node->link_qhead, link_qnode) {

	    /*
	     * Is this a connector link ?
	     */
	    if (link->key.remote_node_id[7] == CONNECTOR_MARKER) {
		lsdb_reset_attr_template(&attr_template);

		attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
		attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
		attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_PTP;

		memcpy(attr_template.key.link.remote_node_id, link->key.remote_node_id, 4);
		memcpy(attr_template.key.link.local_node_id, link->key.local_link_id, 4);
		attr_template.key.link.metric = link->link_metric;
		lsdb_add_node_attr(node, &attr_template);
		continue;
	    }

            /*
	     * Generate a ptp neighbor for each link
	     * TODO Type-2 LSA handling.
	     */
            lsdb_reset_attr_template(&attr_template);

            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_link_prefix.address, sizeof(ipv4addr_t));
            inc = lspgen_get_prefix_inc(AF_INET, ctx->ipv4_link_prefix.len);
            addr += link->link_index * inc;
	    addr_offset = 0;
	    if (lspgen_load_addr(link->key.remote_node_id, 4) < lspgen_load_addr(link->key.local_node_id, 4)) {
		addr_offset = 1;
	    }

	    lspgen_store_addr(addr + addr_offset, attr_template.key.link.local_node_id, 4);

	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
	    attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_PTP;
            memcpy(attr_template.key.link.remote_node_id, link->key.remote_node_id, 4);
	    metric = link->link_metric;
	    if (metric > 65535) {
		metric = 65535;
	    }
            attr_template.key.link.metric = metric;
            lsdb_add_node_attr(node, &attr_template);

            /* Generate an IPv4 prefix for each link */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, sizeof(ipv4addr_t));
            attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_link_prefix.len;
            attr_template.key.prefix.metric = metric;

	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
	    attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_STUB;
            lsdb_add_node_attr(node, &attr_template);
        }

	nodes_left--;
    } while (dict_itor_next(itor));

    dict_itor_free(itor);
}

/*
 * Walk the graph of the LSDB and add the required node/link attributes for OSPFv3 LSP generation.
 */
void
lspgen_gen_ospf3_attr(struct lsdb_ctx_ *ctx)
{
    struct lsdb_node_ *node;
    struct lsdb_link_ *link;
    struct lsdb_attr_ attr_template;
    dict_itor *itor;
    __uint128_t addr, inc, ext_addr6, ext_incr6, addr_offset;
    uint32_t ext_per_node, metric;

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

    /*
     * For external routes load the first address of the pool.
     */
    ext_addr6 = lspgen_load_addr((uint8_t*)&ctx->ipv6_ext_prefix.address, IPV6_ADDR_LEN);
    ext_incr6 = lspgen_get_prefix_inc(AF_INET6, ctx->ipv6_ext_prefix.len);

    do {
        node = *dict_itor_datum(itor);

	/* Host name */
        if (node->node_name) {
            lsdb_reset_attr_template(&attr_template);
	    //attr_template.key.ordinal = 1;
	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_RI;
            attr_template.key.attr_cp[2] = OSPF_TLV_HOSTNAME;
            strncpy(attr_template.key.hostname, node->node_name, sizeof(attr_template.key.hostname)-1);
            lsdb_add_node_attr(node, &attr_template);
        }

        /* IPv6 loopback prefix */
        lsdb_reset_attr_template(&attr_template);
        addr = lspgen_load_addr((uint8_t*)&ctx->ipv6_node_prefix.address, IPV6_ADDR_LEN);
        lspgen_store_addr(addr, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
        attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_node_prefix.len;
	attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	attr_template.key.attr_cp[1] = OSPF_LSA_INTRA_AREA_PREFIX;
	attr_template.key.attr_cp[2] = OSPF_IA_PREFIX_LSA_PREFIX;
        lsdb_add_node_attr(node, &attr_template);

#if 0
        if (!ctx->no_sr) {
	    lsdb_reset_attr_template(&attr_template);
	    lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
	    attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_node_prefix.len;
	    attr_template.key.prefix.sid = node->node_index;

            attr_template.key.ordinal = 1;
	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_EP;
	    attr_template.key.attr_cp[2] = OSPF_TLV_EXTENDED_PREFIX_RANGE;
	    lsdb_add_node_attr(node, &attr_template);
	}
        addr += node->node_index;
#endif

        /* external prefixes */
        ext_per_node = ctx->num_ext / ctx->num_nodes;
        while (ext_per_node--) {
            /* ipv6 external prefix */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(ext_addr6, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
            attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_ext_prefix.len;
            attr_template.key.prefix.metric = 100;
	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_EXTERNAL;
	    attr_template.key.start_tlv = true;
            lsdb_add_node_attr(node, &attr_template);
            ext_addr6 += ext_incr6;
        }

        if (!ctx->no_sr) {
            /* SR capability */
            lsdb_reset_attr_template(&attr_template);
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t));
            addr += node->node_index;
            lspgen_store_addr(addr, attr_template.key.cap.router_id, sizeof(ipv4addr_t));
            attr_template.key.cap.srgb_base = ctx->srgb_base;
            attr_template.key.cap.srgb_range = ctx->srgb_range;
	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_RI;
	    attr_template.key.attr_cp[2] = OSPF_TLV_SID_LABEL_RANGE;
	    //attr_template.key.ordinal = 1;
            lsdb_add_node_attr(node, &attr_template);
        }

        /*
         * Walk all of our neighbors.
         */
        CIRCLEQ_FOREACH(link, &node->link_qhead, link_qnode) {

	    /*
	     * Is this a connector link ?
	     */
	    if (link->key.remote_node_id[7] == CONNECTOR_MARKER) {
		lsdb_reset_attr_template(&attr_template);

		attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
		attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
		attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_PTP;

		memcpy(attr_template.key.link.remote_node_id, link->key.remote_node_id, 4);
		memcpy(attr_template.key.link.local_node_id, link->key.local_link_id, 4);
		attr_template.key.link.metric = link->link_metric;
		lsdb_add_node_attr(node, &attr_template);
		continue;
	    }

	    /*
	     * Generate a ptp neighbor for each link
	     * TODO Type-2 LSA handling.
	     */
            lsdb_reset_attr_template(&attr_template);

            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_link_prefix.address, sizeof(ipv4addr_t));
            inc = lspgen_get_prefix_inc(AF_INET, ctx->ipv4_link_prefix.len);
            addr += link->link_index * inc;
	    addr_offset = 0;
	    if (lspgen_load_addr(link->key.remote_node_id, 4) < lspgen_load_addr(link->key.local_node_id, 4)) {
		addr_offset = 1;
	    }

	    lspgen_store_addr(addr + addr_offset, attr_template.key.link.local_node_id, 4);

	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
	    attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_PTP;
            memcpy(attr_template.key.link.remote_node_id, link->key.remote_node_id, 4);
	    metric = link->link_metric;
	    if (metric > 65535) {
		metric = 65535;
	    }
            attr_template.key.link.metric = metric;
            lsdb_add_node_attr(node, &attr_template);

#if 0
            /* Generate an IPv6 prefix for each link */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
            attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_link_prefix.len;
            attr_template.key.prefix.metric = metric;

	    attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
	    attr_template.key.attr_cp[1] = OSPF_LSA_INTRA_AREA_PREFIX;
	    attr_template.key.attr_cp[2] = OSPF_IA_PREFIX_LSA_PREFIX;
            lsdb_add_node_attr(node, &attr_template);
#endif
	}

    } while (dict_itor_next(itor));

    dict_itor_free(itor);
}

void
lspgen_init_ctx(struct lsdb_ctx_ *ctx)
{
    CIRCLEQ_INIT(&ctx->packet_change_qhead);
    timer_init_root(&ctx->timer_root);

    ctx->protocol_id = PROTO_ISIS;

    ctx->num_nodes = 10; /* Number of nodes */

    /* IS-IS area */
    ctx->area[0].address[0] = 0x49;
    ctx->area[0].address[1] = 0x00;
    ctx->area[0].address[2] = 0x01;
    ctx->area[0].len = 24;

    ctx->topology_id.level = 1;
    ctx->sequence = 1;
    ctx->authentication_type = ISIS_AUTH_NONE;
    ctx->seed = 0x74522142; /* RtB! */
    ctx->lsp_lifetime = 65535;

    /* ipv4 link prefix */
    inet_pton(AF_INET, "172.16.0.0", &ctx->ipv4_link_prefix.address);
    ctx->ipv4_link_prefix.len = 31;

    /* ipv4 loopback prefix */
    inet_pton(AF_INET, "192.168.0.0", &ctx->ipv4_node_prefix.address);
    ctx->ipv4_node_prefix.len = 32;

    /* ipv4 external prefix */
    inet_pton(AF_INET, "10.0.0.0", &ctx->ipv4_ext_prefix.address);
    ctx->ipv4_ext_prefix.len = 28;

    /* ipv6 link prefix */
    inet_pton(AF_INET6, "fc00::ac10:0", &ctx->ipv6_link_prefix.address);
    ctx->ipv6_link_prefix.len = 127;

    /* ipv6 loopback prefix */
    inet_pton(AF_INET6, "fc00::c0a8:0", &ctx->ipv6_node_prefix.address);
    ctx->ipv6_node_prefix.len = 128;

    /* ipv6 external prefix */
    inet_pton(AF_INET6, "fc00::0a00:0", &ctx->ipv6_ext_prefix.address);
    ctx->ipv6_ext_prefix.len = 124;

    /* label */
    ctx->srgb_base = 10000;
    ctx->srgb_range = 2000;

    /* MRT must haves */
    time(&ctx->now);
}

struct ipv4_prefix_ *
lspgen_compute_end_prefix4(struct ipv4_prefix_ *start_prefix, unsigned int num_prefixes)
{
    __uint128_t addr, prefix_inc;
    static struct ipv4_prefix_ end_prefix;

    end_prefix = *start_prefix;

    if (!num_prefixes) {
        return &end_prefix;
    }

    prefix_inc = lspgen_get_prefix_inc(AF_INET, start_prefix->len);
    addr = lspgen_load_addr((uint8_t *)&start_prefix->address, 4);
    addr += prefix_inc * (num_prefixes-1);
    lspgen_store_addr(addr, (uint8_t *)&end_prefix.address, 4);

    return &end_prefix;
}

struct ipv6_prefix_ *
lspgen_compute_end_prefix6(struct ipv6_prefix_ *start_prefix, unsigned int num_prefixes)
{
    __uint128_t addr, prefix_inc;
    static struct ipv6_prefix_ end_prefix;

    end_prefix = *start_prefix;

    if (!num_prefixes) {
    return &end_prefix;
    }

    prefix_inc = lspgen_get_prefix_inc(AF_INET6, start_prefix->len);
    addr = lspgen_load_addr((uint8_t *)&start_prefix->address, IPV6_ADDR_LEN);
    addr += prefix_inc * (num_prefixes-1);
    lspgen_store_addr(addr, (uint8_t *)&end_prefix.address, IPV6_ADDR_LEN);

    return &end_prefix;
}

void
lspgen_log_ctx(struct lsdb_ctx_ *ctx)
{
    struct ipv4_prefix_ *end_prefix4;
    struct ipv6_prefix_ *end_prefix6;
    uint32_t idx;

    LOG_NOARG(NORMAL, "LSP generation parameters\n");
    LOG(NORMAL, " Protocol %s\n", lsdb_format_proto(ctx));

    /*
     * No Area specified ? Show at least the default.
     */
    if (!ctx->num_area) {
        ctx->num_area = 1;
    }

    if (ctx->protocol_id == PROTO_ISIS) {
	for (idx = 0; idx < ctx->num_area; idx++) {
	    LOG(NORMAL, " Area %s\n", format_iso_prefix(&ctx->area[idx]));
	}
	LOG(NORMAL, " Level %u\n", ctx->topology_id.level);

    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	    LOG(NORMAL, " Area %s\n", format_ipv4_address(&ctx->topology_id.area));
    }
    LOG(NORMAL, " Sequence 0x%x, lsp-lifetime %u%s\n",
	ctx->sequence, ctx->lsp_lifetime,
	ctx->purge ? ", Purge" : "");

    if (ctx->authentication_key) {
        LOG(NORMAL, " Authentication-key %s, Authentication-type %s\n",
            ctx->authentication_key, val2key(isis_auth_names, ctx->authentication_type));
    }
    if (!ctx->no_ipv4) {
        end_prefix4 = lspgen_compute_end_prefix4(&ctx->ipv4_node_prefix, ctx->num_nodes);
        LOG(NORMAL, " IPv4 Node Base Prefix %s, End Prefix %s, %u prefixes\n",
            format_ipv4_prefix(&ctx->ipv4_node_prefix),
            format_ipv4_prefix(end_prefix4), ctx->num_nodes);

        end_prefix4 = lspgen_compute_end_prefix4(&ctx->ipv4_link_prefix, ctx->num_nodes*2);
        LOG(NORMAL, " IPv4 Link Base Prefix %s, End Prefix %s, %u prefixes\n",
            format_ipv4_prefix(&ctx->ipv4_link_prefix),
            format_ipv4_prefix(end_prefix4), ctx->num_nodes*2);

        end_prefix4 = lspgen_compute_end_prefix4(&ctx->ipv4_ext_prefix, ctx->num_ext);
        LOG(NORMAL, " IPv4 External Base Prefix %s, End Prefix %s, %u prefixes\n",
            format_ipv4_prefix(&ctx->ipv4_ext_prefix),
            format_ipv4_prefix(end_prefix4), ctx->num_ext);
    }
    if (!ctx->no_ipv6) {
        end_prefix6 = lspgen_compute_end_prefix6(&ctx->ipv6_node_prefix, ctx->num_nodes);
        LOG(NORMAL, " IPv6 Node Base Prefix %s, End Prefix %s, %u prefixes\n",
            format_ipv6_prefix(&ctx->ipv6_node_prefix),
            format_ipv6_prefix(end_prefix6), ctx->num_nodes);

        end_prefix6 = lspgen_compute_end_prefix6(&ctx->ipv6_link_prefix, ctx->num_nodes*2);
        LOG(NORMAL, " IPv6 Link Base Prefix %s, End Prefix %s, %u prefixes\n",
            format_ipv6_prefix(&ctx->ipv6_link_prefix),
            format_ipv6_prefix(end_prefix6), ctx->num_nodes);

        end_prefix6 = lspgen_compute_end_prefix6(&ctx->ipv6_ext_prefix, ctx->num_ext);
        LOG(NORMAL, " IPv6 External Base Prefix %s, End Prefix %s, %u prefixes\n",
            format_ipv6_prefix(&ctx->ipv6_ext_prefix),
            format_ipv6_prefix(end_prefix6), ctx->num_ext);
    }
    if (!ctx->no_sr) {
        LOG(NORMAL, " SRGB base %u, range %u\n", ctx->srgb_base, ctx->srgb_range);
    }
}

/*
 * Compute the SRGB range to be large enough to hold indexes for ipv4 and ipv6 SIDs.
 */
void
lspgen_compute_srgb_range(struct lsdb_ctx_ *ctx)
{
    unsigned int range;

    if (ctx->no_ipv4 && ctx->no_ipv6) {
        ctx->srgb_range = 0;
        return;
    }

    range = ctx->num_nodes * 2;
    if (ctx->no_ipv4) {
        range = ctx->num_nodes;
    }

    if (ctx->no_ipv6) {
        range = ctx->num_nodes;
    }

    ctx->srgb_range = range;
}

/*
 * Add  a connector string in the form of an
 * iso remote_id xxxx.xxxx.xxxx.xx or
 * ipv4 remote_id:local_ip xxx.xxx.xxx.xxx:yyy.yyy.yyy.yyy
*/
void
lspgen_add_connector(struct lsdb_ctx_ *ctx, char *conn_src)
{
    long long int iso_node_id; /* Used for ISO */
    uint32_t remote_id, local_ip; /* Used for IP */
    char conn_dst[32];
    size_t src_len, dst_len;
    uint32_t src, dst, shift;
    bool colon_found;

    if (ctx->num_connector >= (sizeof(ctx->connector)/sizeof(ctx->connector[0]))) {
        LOG(ERROR, "Maximum connector limit (%u) exceeded\n", ctx->num_connector);
        return;
    }

    src_len = strlen(conn_src);

    if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {

	char *tok;

	/*
	 * First check if this is an remote-id:local_ip format.
	 */
	colon_found = false;
	for (src = 0; src < src_len; src++) {
	    if (conn_src[src] == ':') {
		colon_found = true;
		break;
	    }
	}

	if (!colon_found) {
	    LOG(ERROR, "Connector '%s' not in remote_id:local_ip format\n", conn_src);
	    return;
	}

	remote_id = 0;
	local_ip = 0;
	tok = strtok(conn_src, ":");
        if (tok && scan_ipv4_address(conn_src, &remote_id)) {
	    tok = strtok(NULL, ":");
	    if (tok && scan_ipv4_address(tok, &local_ip)) {
		write_le_uint(ctx->connector[ctx->num_connector].remote_node_id, 4, remote_id);
		write_le_uint(ctx->connector[ctx->num_connector].local_link_id, 4, local_ip);
            }
        }

	LOG(NORMAL, "Add connector to %s:%s\n",
	    format_ipv4_address(&remote_id),
	    format_ipv4_address(&local_ip));
	ctx->num_connector++;

    } else if (ctx->protocol_id == PROTO_ISIS) {

	/* ISO node-ID format */
	memset(conn_dst, 0, sizeof(conn_dst));
	conn_dst[0] = '0';
	conn_dst[1] = 'x';
	dst = 2;
	for (src = 0; src < src_len; src++) {

	    if (dst >= sizeof(conn_dst)-2) {
		break;
	    }

	    if (conn_src[src] >= 'a' && conn_src[src] <= 'f') {
		conn_dst[dst++] = conn_src[src];
		continue;
	    }
	    if (conn_src[src] >= '0' && conn_src[src] <= '9') {
		conn_dst[dst++] = conn_src[src];
		continue;
	    }
	}
	iso_node_id = strtoll(conn_dst, NULL, 16);

	dst_len = strlen(&conn_dst[2]);
	if (dst_len > 16) {
	    LOG(ERROR, "illegal connector length %s\n", conn_src);
	    return;
	}

	shift = (16 - dst_len) * 4;
	write_be_uint(ctx->connector[ctx->num_connector].remote_node_id, 8, iso_node_id << shift);

	LOG(NORMAL, "Add connector to %s\n",
	    lsdb_format_node_id(ctx->connector[ctx->num_connector].remote_node_id));
	ctx->num_connector++;
    }
}

/* Get out of event loop */
void
lspgen_quit_loop (void)
{
    loop_running = false;
}

void
lspgen_sig_handler (int signum)
{
    LOG(NORMAL, "Received %s signal\n", strsignal(signum));

    switch (signum) {
        case SIGINT:
            lspgen_quit_loop();
            break;
        default:
            break;
    }
}

int
main(int argc, char *argv[])
{
    int opt, idx, res;
    struct lsdb_ctx_ *ctx;

    /*
     * Init default options.
     */
    log_id[NORMAL].enable = true;
    log_id[ERROR].enable = true;

    ctx = lsdb_alloc_ctx("default");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }
    lspgen_init_ctx(ctx);

    /*
     * Parse options.
     */
    idx = 0;
    while ((opt = getopt_long(argc, argv, "vha:c:C:e:f:g:Gl:L:m:M:n:K:N:p:P:q:Qr:s:S:t:T:V:w:x:X:yzZ",
                              long_options, &idx)) != -1) {
        switch (opt) {
            case 'v':
                lspgen_print_version();
                exit(0);
	    case 'G':
		ctx->purge = true;
		break;
	    case 'P':
		ctx->protocol_id = key2val(proto_names, optarg);
		if (ctx->protocol_id == PROTO_OSPF2) {
		    ctx->no_ipv6 = true;
		}
		if (ctx->protocol_id == PROTO_OSPF3) {
		    ctx->no_ipv4 = true;
		}
		if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
		    ctx->topology_id.area = 0; /* reset area */
		    ctx->sequence = 0x80000001;
		    ctx->lsp_lifetime = 3600;
		}
		break;
            case 'r':
                if (ctx->config_filename) {
                    ctx->config_write = false;
                    free(ctx->config_filename);
                }
                ctx->config_filename = strdup(optarg);
                ctx->config_read = true;
                break;
            case 'w':
                if (ctx->config_filename) {
                ctx->config_read = false;
                free(ctx->config_filename);
                }
                ctx->config_filename = strdup(optarg);
                ctx->config_write = true;
                break;
            case 'a':
		if (ctx->protocol_id == PROTO_ISIS) {
		    if (ctx->num_area < 3) {
			scan_iso_prefix(optarg, &ctx->area[ctx->num_area++]);
		    }
		} else {
		    /* ospf2 and ospf3 */
		    scan_ipv4_address(optarg, &ctx->topology_id.area);
		}
                break;
            case 'M':
                ctx->lsp_lifetime = atoi(optarg);
                if (ctx->lsp_lifetime < 120) {
                    ctx->lsp_lifetime = 120;
                    LOG(ERROR, "Set lsp-lifetime to min %us\n", ctx->lsp_lifetime);
                }
                break;
            case 'y':
                /* no-sr */
                ctx->no_sr = true;
                break;
            case 'z':
                /* no-ipv4 */
                ctx->no_ipv4 = true;
                break;
            case 'Z':
                /* no-ipv6 */
                ctx->no_ipv6 = true;
                break;
            case 'T':
                /* authentication-type */
                ctx->authentication_type = get_authentication_type(optarg);
                break;
            case 't':
                /* logging */
                log_enable(optarg);
                break;
            case 'c':
                ctx->num_nodes = strtol(optarg, NULL, 10);
                if (ctx->num_nodes < 5) {
                    ctx->num_nodes = 5;
                    LOG(ERROR, "Set node count to minimal %u\n", ctx->num_nodes);
                }
                lspgen_compute_srgb_range(ctx);
                break;
            case 'C':
                /* connector */
                lspgen_add_connector(ctx, optarg);
                break;
            case 'n':
                /* base prefix for ipv4 loopbacks */
                scan_ipv4_prefix(optarg, &ctx->ipv4_node_prefix);
                break;
            case 'm':
                ctx->mrt_filename = strdup(optarg);
                break;
            case 'N':
                /* base prefix for ipv6 loopbacks */
                scan_ipv6_prefix(optarg, &ctx->ipv6_node_prefix);
                break;
            case 'l':
                /* base prefix for ipv4 interface */
                scan_ipv4_prefix(optarg, &ctx->ipv4_link_prefix);
                break;
            case 'L':
                /* base prefix for ipv6 interfaces */
                scan_ipv6_prefix(optarg, &ctx->ipv6_link_prefix);
                break;
            case 'x':
                /* base prefix for ipv4 externals */
                scan_ipv4_prefix(optarg, &ctx->ipv4_ext_prefix);
                break;
            case 'X':
                /* base prefix for ipv6 externals */
                scan_ipv6_prefix(optarg, &ctx->ipv6_ext_prefix);
                break;
            case 'e':
                ctx->num_ext = strtol(optarg, NULL, 10);
                break;
            case 'K':
                /* authentication-key */
                ctx->authentication_key = strdup(optarg);
                if (ctx->authentication_type == ISIS_AUTH_NONE) {
                    ctx->authentication_type = ISIS_AUTH_SIMPLE;
                }
                break;
            case 'g':
                /* export LSDB as graphviz file and render into a SVG */
                ctx->graphviz_filename = strdup(optarg);
                break;
            case 'p':
                /* export LSDB as pcap file */
                ctx->pcap_filename = strdup(optarg);
                break;
            case 'f':
                /* export traffic stream file */
                ctx->stream_filename = strdup(optarg);
                break;
            case 'q':
                /* sequence */
                ctx->sequence = strtol(optarg, NULL, 0);
                if (ctx->sequence == 0) {
		    if (ctx->protocol_id == PROTO_ISIS) {
			ctx->sequence = 1;
		    } else {
			ctx->sequence = 0x80000001;
		    }
                }
                break;
            case 'Q':
                /* Quit event loop after draining LSDB once  */
                ctx->quit_loop = true;
                break;
            case 's':
                /* seed value such that random graph generation becomes deterministic */
                ctx->seed = strtol(optarg, NULL, 0);
                break;
            case 'S':
                /* open control socket to BNG Blaster */
                ctx->ctrl_socket_path = strdup(optarg);
                break;
            case 'V':
                /* level */
                if (ctx->protocol_id != PROTO_ISIS) {
                    LOG(ERROR, "Level may not be set for protocol %s\n", lsdb_format_proto(ctx));
                    exit(EXIT_FAILURE);
		}
                ctx->topology_id.level = atoi(optarg);
                if (ctx->topology_id.level < 1 || ctx->topology_id.level > 2) {
                    LOG(ERROR, "Level %u is not supported\n", ctx->topology_id.level);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h': /* fall through */
            default:
                lspgen_print_usage();
                exit(EXIT_FAILURE);
        }
    }

    /*
     * Display options.
     */
    lspgen_log_ctx(ctx);

    /*
     * Read the link-state database from a config file.
     */
    if (ctx->config_read && ctx->config_filename) {
        lspgen_read_config(ctx);
    } else {
        /*
         * Generate a random graph.
         */
        lsdb_init_graph(ctx);

        /*
         * Generate the node and link attributes.
         */
	if (ctx->protocol_id == PROTO_ISIS) {
	    lspgen_gen_isis_attr(ctx);
	} else if (ctx->protocol_id == PROTO_OSPF2) {
	    lspgen_gen_ospf2_attr(ctx);
	} else if (ctx->protocol_id == PROTO_OSPF3) {
	    lspgen_gen_ospf3_attr(ctx);
	}
    }

    /*
     * Bump the sequence numbers if there is a cache file.
     */
    lspgen_read_seq_cache(ctx);

    /*
     * Serialize the Link-State packets.
     */
    lspgen_gen_packet(ctx);

    /*
     * Dump the lsdb into a PCAP file.
     */
    if (ctx->pcap_filename) {
        lspgen_dump_pcap(ctx);
    }

    /*
     * Dump the lsdb into a MRT file.
     */
    if (ctx->mrt_filename) {
        lspgen_dump_mrt(ctx);
    }

    /*
     * Dump the lsdb into a graphviz file.
     */
    if (ctx->graphviz_filename) {
        char cmd[256];
        lsdb_dump_graphviz(ctx);
        snprintf(cmd, sizeof(cmd), "dot -Tsvg %s.dot -o %s.svg", ctx->graphviz_filename, ctx->graphviz_filename);
        res = system(cmd); /* convert to svg */
        if (!res) {
            LOG(NORMAL, "Converted graphviz file %s.dot into %s.svg\n",
            ctx->graphviz_filename, ctx->graphviz_filename);
        } else {
            LOG(ERROR, "Could not convert graphviz file %s.dot into %s.svg\n",
            ctx->graphviz_filename, ctx->graphviz_filename);
        }
    }

    /*
     * Generate a traffic stream file description.
     */
    if (ctx->stream_filename) {
        lspgen_dump_stream(ctx);
    }

    /*
     * Generate a config file from the link-state database.
     */
    if (ctx->config_write && ctx->config_filename) {
        lspgen_write_config(ctx);
    }

    /*
     * Open Control socket.
     */
    if (ctx->ctrl_socket_path) {
        ctx->ctrl_io_buf.start_idx = 0;
        ctx->ctrl_io_buf.idx = 0;
        ctx->ctrl_io_buf.size = CTRL_SOCKET_BUFSIZE;
        ctx->ctrl_io_buf.data = malloc(ctx->ctrl_io_buf.size);
        if (!ctx->ctrl_io_buf.data) {
            goto EXIT;
        }

        timer_add_periodic(&ctx->timer_root, &ctx->ctrl_socket_connect_timer,
                           "connect", 1, 0, ctx, &lspgen_ctrl_connect_cb);

        /*
        * Wakeup at least once a second doing nothing,
         * such that we do not sleep while user tries to quit the timer loop.
         */
        timer_add_periodic(&ctx->timer_root, &ctx->ctrl_socket_wakeup_timer,
                           "wakeup", 1, 0, ctx, &lspgen_ctrl_wakeup_cb);

        /*
         * Block SIGPIPE. This happens when a session disconnects.
         * EPIPE gets handled when writing the buffer.
         */
        signal(SIGPIPE, SIG_IGN);

        /*
         * Keep running until Ctrl-C is hit.
         */
        signal(SIGINT, lspgen_sig_handler);

        while (loop_running) {
            timer_walk(&ctx->timer_root);
        }
    }

    /*
     * Write the sequence cache file.
     */
    lspgen_write_seq_cache(ctx);

    /*
     * Flush and close all we have.
     */
EXIT:
    lsdb_delete_ctx(ctx);
    return 0;
}
