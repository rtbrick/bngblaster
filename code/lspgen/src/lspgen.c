/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>

#include "libdict/dict.h"

#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"
#include "lspgen_ospf.h"

/*
 * Globals
 */
volatile sig_atomic_t loop_running = true;

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
    {"control-instance", required_argument, NULL, 'I'},
    {"ipv4-link-prefix", required_argument, NULL, 'l'},
    {"ipv6-link-prefix", required_argument, NULL, 'L'},
    {"ipv4-node-prefix", required_argument, NULL, 'n'},
    {"ipv6-node-prefix", required_argument, NULL, 'N'},
    {"ipv4-external-prefix", required_argument, NULL, 'x'},
    {"ipv6-external-prefix", required_argument, NULL, 'X'},
    {"link-multiplier", required_argument, NULL, 'u'},
    {"lsp-lifetime", required_argument, NULL, 'M'},
    {"no-ipv4", no_argument, NULL, 'z'},
    {"no-ipv6", no_argument, NULL, 'Z'},
    {"no-sr", no_argument, NULL, 'y'},
    {"sr-algo", required_argument, NULL, 'A'},
    {"flex-algo", required_argument, NULL, 'F'},
    {"link-delay", required_argument, NULL, 'D'},
    {"te-metric", required_argument, NULL, 'E'},
    {"node-msd", required_argument, NULL, 'B'},
    {"elc", no_argument, NULL, 'O'},
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
 * Protocol / name translation table.
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

lsdb_proto_id_t
lsdb_scan_proto (const char *protocol_name)
{
    return key2val(proto_names, protocol_name);
}

/*
 * Authentication type / name translation table.
 */
struct keyval_ auth_type_names[] = {
    { ISIS_AUTH_NONE, "none" },
    { ISIS_AUTH_SIMPLE, "simple" },
    { ISIS_AUTH_MD5, "md5" },
    { 0, NULL}
};

char *
lspgen_print_arg_options(struct keyval_ *ptr)
{
    static char buf[128];
    size_t len;

    len = 0;
    buf[0] = 0;

    if (!ptr) {
        return buf;
    }

    while (ptr->key && len < sizeof(buf)) {
        len += snprintf(buf+len, sizeof(buf)-len, "%s%s", len ? "|" : " ", ptr->key);
        ptr++;
    }
    return buf;
}

char *
lspgen_print_usage_arg(struct option *option)
{
    if (option->has_arg == 1) {

        /* protocol */
        if (strcmp(option->name, "protocol") == 0) {
            return lspgen_print_arg_options(proto_names);
        }

        /* logging */
        if (strcmp(option->name, "log") == 0) {
            return lspgen_print_arg_options(log_names);
        }

        /* authentication-type */
        if (strcmp(option->name, "authentication-type") == 0) {
            return lspgen_print_arg_options(auth_type_names);
        }

        /* SR algorithms */
        if (strcmp(option->name, "sr-algo") == 0) {
            return " <algo,...>";
        }

        /* Flex-Algo definitions */
        if (strcmp(option->name, "flex-algo") == 0) {
            return " <algo:igp|min-delay|te[:priority],...>";
        }

        /* Random link attribute ranges */
        if (strcmp(option->name, "link-delay") == 0 ||
            strcmp(option->name, "te-metric") == 0) {
            return " <min>[:<max>]";
        }

        /* filenames */
        if (strstr(option->name, "file")) {
            return " <filename>";
        }

        /* IP prefixes */
        if (strstr(option->name, "prefix")) {
            return " <ip-prefix>";
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
    } else {
        printf("Version: DEV\n");
    }
    if(sizeof(COMPILER_ID)-1 + sizeof(COMPILER_VERSION)-1) {
        printf("Compiler: %s (%s)\n", COMPILER_ID, COMPILER_VERSION);
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
    while (auth_type_names[idx].key) {
        if (strcmp(auth_type_names[idx].key, auth_type_name) == 0) {
            return auth_type_names[idx].val;
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
    *stack_idx -= idx;
    if (*stack_idx) {
        stack[0] = stack[idx];
    }
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
         * Load a byte and do the decimal conversion.
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
 * Return the number of SR algorithms used for node SIDs.
 */
static uint32_t
lspgen_sr_algo_slots(struct lsdb_ctx_ *ctx)
{
    return ctx->sr_algo_count ? ctx->sr_algo_count : 1;
}

/*
 * Return the SRGB range required for ipv4 and ipv6 node SIDs of all SR algorithms.
 * The IS-IS ipv6 node SIDs start at half of the SRGB range, even without ipv4.
 * OSPF uses one node SID per node.
 */
static uint32_t
lspgen_required_srgb_range(struct lsdb_ctx_ *ctx)
{
    uint32_t range = ctx->num_nodes * lspgen_sr_algo_slots(ctx);

    if (ctx->protocol_id == PROTO_ISIS && !ctx->no_ipv6) {
        range *= 2;
    }
    return range;
}

/*
 * Compute the SRGB range to be large enough to hold indexes for ipv4 and ipv6 SIDs.
 */
void
lspgen_compute_srgb_range(struct lsdb_ctx_ *ctx)
{
    ctx->srgb_range = lspgen_required_srgb_range(ctx);
}

/*
 * Grow the SRGB range if required, e.g. for additional SR algorithms.
 */
static void
lspgen_check_srgb_range(struct lsdb_ctx_ *ctx)
{
    uint32_t range;

    if (ctx->no_sr) {
        return;
    }
    range = lspgen_required_srgb_range(ctx);
    if (ctx->srgb_range < range) {
        ctx->srgb_range = range;
    }
}

/*
 * Node SID index layout:
 * ipv4: [algo slot 0 nodes][algo slot 1 nodes]...
 * ipv6: same layout starting at half of the SRGB range.
 */
static uint32_t
lspgen_node_sid_index(struct lsdb_ctx_ *ctx, lsdb_node_t *node, uint32_t slot, bool ipv6)
{
    uint32_t base = 0;

    if (ipv6) {
        base = ctx->srgb_range/2;
    }
    return base + slot * ctx->num_nodes + node->node_index;
}

/*
 * Add one node SID per SR algorithm to a prefix attribute.
 */
static void
lspgen_add_node_sids(struct lsdb_ctx_ *ctx, lsdb_node_t *node, lsdb_attr_t *attr, bool ipv6)
{
    uint32_t slot;

    for (slot = 0; slot < lspgen_sr_algo_slots(ctx); slot++) {
        attr->key.prefix.algos[slot].sid = lspgen_node_sid_index(ctx, node, slot, ipv6);
        attr->key.prefix.algos[slot].algo = ctx->sr_algo_count ? ctx->sr_algo[slot] : 0;
        attr->key.prefix.algos[slot].flags = LSDB_PREFIX_ALGO_SID;
    }
    attr->key.prefix.algo_count = slot;
}

/*
 * Parse a comma separated list of SR algorithms,
 * which are 0 (SPF), 1 (strict SPF) or 128-255 (Flex-Algo).
 */
static bool
lspgen_parse_sr_algo(struct lsdb_ctx_ *ctx, char *arg)
{
    char *list, *tok, *end, *save = NULL;
    long algo;
    int idx;

    ctx->sr_algo_count = 0;
    list = strdup(arg);
    if (!list) {
        return false;
    }
    for (tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        algo = strtol(tok, &end, 10);
        if (*end || end == tok || algo < 0 || algo > 255 || (algo > 1 && algo < 128)) {
            LOG(ERROR, "Invalid SR algorithm %s\n", tok);
            free(list);
            return false;
        }
        for (idx = 0; idx < ctx->sr_algo_count; idx++) {
            if (ctx->sr_algo[idx] == algo) {
                LOG(ERROR, "Duplicate SR algorithm %ld\n", algo);
                free(list);
                return false;
            }
        }
        if (ctx->sr_algo_count >= LSDB_MAX_PREFIX_ALGO) {
            LOG(ERROR, "Maximum %d SR algorithms supported\n", LSDB_MAX_PREFIX_ALGO);
            free(list);
            return false;
        }
        ctx->sr_algo[ctx->sr_algo_count++] = algo;
    }
    free(list);
    if (!ctx->sr_algo_count) {
        LOG_NOARG(ERROR, "Missing SR algorithm\n");
        return false;
    }
    return true;
}

/*
 * Parse a comma separated list of Flex-Algo definitions
 * in the format <algo>:<metric-type>[:<priority>].
 */
static bool
lspgen_parse_flex_algo(struct lsdb_ctx_ *ctx, char *arg)
{
    char *list, *tok, *field, *end, *save = NULL, *save_field = NULL;
    lsdb_attr_fad_t *fad;
    long value;
    int idx;

    if (!ctx->fad) {
        ctx->fad = calloc(LSDB_MAX_FLEX_ALGO, sizeof(lsdb_attr_fad_t));
        if (!ctx->fad) {
            return false;
        }
    }
    ctx->fad_count = 0;
    list = strdup(arg);
    if (!list) {
        return false;
    }
    for (tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (ctx->fad_count >= LSDB_MAX_FLEX_ALGO) {
            LOG(ERROR, "Maximum %d Flex-Algo definitions supported\n", LSDB_MAX_FLEX_ALGO);
            goto ERROR;
        }
        fad = &ctx->fad[ctx->fad_count];
        memset(fad, 0, sizeof(*fad));
        fad->priority = LSDB_FAD_DEFAULT_PRIORITY;

        /* algo */
        field = strtok_r(tok, ":", &save_field);
        value = field ? strtol(field, &end, 10) : 0;
        if (!field || *end || value < 128 || value > 255) {
            LOG(ERROR, "Invalid Flex-Algo %s (128 - 255)\n", field ? field : "");
            goto ERROR;
        }
        fad->algo = value;
        for (idx = 0; idx < ctx->fad_count; idx++) {
            if (ctx->fad[idx].algo == fad->algo) {
                LOG(ERROR, "Duplicate Flex-Algo %u\n", fad->algo);
                goto ERROR;
            }
        }

        /* metric type */
        field = strtok_r(NULL, ":", &save_field);
        if (field && !lspgen_scan_fad_metric_type(field, &fad->metric_type)) {
            LOG(ERROR, "Invalid Flex-Algo metric type %s (igp|min-delay|te)\n", field);
            goto ERROR;
        }

        /* priority */
        field = strtok_r(NULL, ":", &save_field);
        if (field) {
            value = strtol(field, &end, 10);
            if (*end || value < 0 || value > 255) {
                LOG(ERROR, "Invalid Flex-Algo priority %s\n", field);
                goto ERROR;
            }
            fad->priority = value;
        }
        ctx->fad_count++;
    }
    free(list);
    return true;

ERROR:
    free(list);
    return false;
}

/*
 * Each Flex-Algo requires node SIDs and must be advertised
 * in the SR-Algorithm subTLV, which includes algorithm 0 by default.
 */
static bool
lspgen_add_flex_algo_to_sr_algo(struct lsdb_ctx_ *ctx)
{
    int idx, sr_idx;

    if (!ctx->fad_count) {
        return true;
    }
    if (!ctx->sr_algo_count) {
        ctx->sr_algo[ctx->sr_algo_count++] = 0;
    }
    for (idx = 0; idx < ctx->fad_count; idx++) {
        for (sr_idx = 0; sr_idx < ctx->sr_algo_count; sr_idx++) {
            if (ctx->sr_algo[sr_idx] == ctx->fad[idx].algo) {
                break;
            }
        }
        if (sr_idx < ctx->sr_algo_count) {
            continue;
        }
        if (ctx->sr_algo_count >= LSDB_MAX_PREFIX_ALGO) {
            LOG(ERROR, "Maximum %d SR algorithms supported\n", LSDB_MAX_PREFIX_ALGO);
            return false;
        }
        ctx->sr_algo[ctx->sr_algo_count++] = ctx->fad[idx].algo;
    }
    return true;
}

/*
 * Parse a value range in the format <min>[:<max>] with values from 1 to 2^24-1.
 */
static bool
lspgen_parse_range(char *arg, uint32_t *min, uint32_t *max)
{
    char *end;
    long value;

    value = strtol(arg, &end, 10);
    if (end == arg || value < 1 || value > ISIS_MAX_TE_VALUE) {
        return false;
    }
    *min = value;
    *max = value;
    if (*end == ':') {
        arg = end + 1;
        value = strtol(arg, &end, 10);
        if (end == arg || value < *min || value > ISIS_MAX_TE_VALUE) {
            return false;
        }
        *max = value;
    }
    return *end == '\0';
}

/*
 * Return a pseudo random value from the range <min> to <max> for a link.
 * The value is derived from both node IDs and the seed, so both
 * directions of a link get the same value and topologies are reproducible.
 */
static uint32_t
lspgen_link_random(struct lsdb_ctx_ *ctx, lsdb_link_t *link, uint32_t salt, uint32_t min, uint32_t max)
{
    uint8_t *a = link->key.local_node_id;
    uint8_t *b = link->key.remote_node_id;
    uint32_t hash = 2166136261u ^ ctx->seed ^ salt; /* FNV-1a */
    int idx;

    if (memcmp(a, b, LSDB_MAX_NODE_ID_SIZE) > 0) {
        a = link->key.remote_node_id;
        b = link->key.local_node_id;
    }
    for (idx = 0; idx < LSDB_MAX_NODE_ID_SIZE; idx++) {
        hash = (hash ^ a[idx]) * 16777619u;
    }
    for (idx = 0; idx < LSDB_MAX_NODE_ID_SIZE; idx++) {
        hash = (hash ^ b[idx]) * 16777619u;
    }
    return min + hash % (max - min + 1);
}

/*
 * Add application-specific link attributes for Flex-Algo, required with
 * Flex-Algo definitions or link delay and TE metric ranges.
 * Unset values default to the IGP metric.
 */
static void
lspgen_add_link_asla(struct lsdb_ctx_ *ctx, lsdb_link_t *link, lsdb_attr_t *attr)
{
    uint32_t default_value;

    if (!ctx->fad_count && !ctx->link_delay_max && !ctx->te_metric_max) {
        return;
    }
    default_value = link->link_metric;
    if (default_value < 1) {
        default_value = 1;
    } else if (default_value > ISIS_MAX_TE_VALUE) {
        default_value = ISIS_MAX_TE_VALUE;
    }
    attr->key.link.asla = true;
    if (ctx->te_metric_max) {
        attr->key.link.te_metric = lspgen_link_random(ctx, link, 1, ctx->te_metric_min, ctx->te_metric_max);
    } else {
        attr->key.link.te_metric = default_value;
    }
    if (ctx->link_delay_max) {
        attr->key.link.min_delay = lspgen_link_random(ctx, link, 2, ctx->link_delay_min, ctx->link_delay_max);
    } else {
        attr->key.link.min_delay = default_value;
    }
    attr->key.link.max_delay = attr->key.link.min_delay;
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

        LOG(LSDB, "Generating node %s (%s) attributes\n",
            lsdb_format_node(node),
            lsdb_format_node_id(node->key.node_id));

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

        /* LSP Buffer size */
        lsdb_reset_attr_template(&attr_template);
        attr_template.key.ordinal = 1;
        attr_template.key.attr_type = ISIS_TLV_LSP_BUFFER_SIZE;
        attr_template.key.lsp_buffer_size = ISIS_DEFAULT_LSP_BUFFER_SIZE;
        lsdb_add_node_attr(node, &attr_template);

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
            lspgen_add_node_sids(ctx, node, &attr_template, false);
        }
        attr_template.key.prefix.node_flag = true;
        attr_template.key.prefix.elc_flag = ctx->elc;
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
            lspgen_add_node_sids(ctx, node, &attr_template, true);
        }
        attr_template.key.prefix.node_flag = true;
        attr_template.key.prefix.elc_flag = ctx->elc;
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
            memcpy(attr_template.key.cap.sr_algo, ctx->sr_algo, ctx->sr_algo_count);
            attr_template.key.cap.sr_algo_len = ctx->sr_algo_count;
            if (ctx->node_msd) {
                attr_template.key.cap.msd[0].type = LSDB_MSD_TYPE_BMI;
                attr_template.key.cap.msd[0].value = ctx->node_msd;
            }
            attr_template.key.attr_type = ISIS_TLV_CAP;
            attr_template.key.ordinal = 1;
            lsdb_add_node_attr(node, &attr_template);

            /* Flex-Algo definitions are advertised by two nodes for redundancy */
            if (node->node_index < 2) {
                for (idx = 0; idx < ctx->fad_count; idx++) {
                    memcpy(ctx->fad[idx].router_id, attr_template.key.cap.router_id, 4);
                    lspgen_add_fad_attr(node, &ctx->fad[idx]);
                }
            }
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
            lspgen_add_link_asla(ctx, link, &attr_template);
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

        LOG(LSDB, "Generating node %s (%s) attributes\n",
            lsdb_format_node(node),
            lsdb_format_node_id(node->key.node_id));

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
        addr += node->node_index;
        lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, sizeof(ipv4addr_t));
        attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_node_prefix.len;
        attr_template.key.prefix.node_flag = true;
        attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
        attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
        attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_STUB;
        lsdb_add_node_attr(node, &attr_template);

        if (!ctx->no_sr) {
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(addr, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, sizeof(ipv4addr_t));
            attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_node_prefix.len;
            attr_template.key.prefix.algos[0].sid = node->node_index;
            attr_template.key.prefix.algos[0].flags = LSDB_PREFIX_ALGO_SID;
            attr_template.key.prefix.algo_count = 1;
            attr_template.key.prefix.node_flag = true;

            attr_template.key.ordinal = 1;
            attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
            attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_EP;
            attr_template.key.attr_cp[2] = OSPF_TLV_EXTENDED_PREFIX;
            attr_template.key.attr_cp[3] = OSPF_SUBTLV_PREFIX_SID;
            lsdb_add_node_attr(node, &attr_template);
        }

        /* external prefixes */
        ext_per_node = ext_left / nodes_left;
        ext_left -= ext_per_node;
        while (ext_per_node--) {
            /* ipv4 external prefix */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(ext_addr4, (uint8_t*)&attr_template.key.prefix.ipv4_prefix.address, 4);
            attr_template.key.prefix.ipv4_prefix.len = ctx->ipv4_ext_prefix.len;
            attr_template.key.prefix.metric = 100;
            attr_template.key.prefix.ext_flag = true;

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
                memcpy(attr_template.key.link.remote_link_id, link->key.remote_link_id, 4);
                memcpy(attr_template.key.link.local_link_id, link->key.local_link_id, 4);
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

            lspgen_store_addr(addr + addr_offset, attr_template.key.link.local_link_id, 4);

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
    __uint128_t addr, inc, ext_addr6, ext_incr6;
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
    ext_addr6 = lspgen_load_addr((uint8_t*)&ctx->ipv6_ext_prefix.address, IPV6_ADDR_LEN);
    ext_incr6 = lspgen_get_prefix_inc(AF_INET6, ctx->ipv6_ext_prefix.len);

    nodes_left = ctx->num_nodes;
    ext_left = ctx->num_ext;

    do {
        node = *dict_itor_datum(itor);

        LOG(LSDB, "Generating node %s (%s) attributes\n",
            lsdb_format_node(node),
            lsdb_format_node_id(node->key.node_id));

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

        /* IPv6 loopback prefix */
        lsdb_reset_attr_template(&attr_template);
        addr = lspgen_load_addr((uint8_t*)&ctx->ipv6_node_prefix.address, IPV6_ADDR_LEN);
        addr += node->node_index;
        lspgen_store_addr(addr, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
        attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_node_prefix.len;
        attr_template.key.prefix.node_flag = true;
        attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
        attr_template.key.attr_cp[1] = OSPF_LSA_INTRA_AREA_PREFIX;
        attr_template.key.attr_cp[2] = OSPF_IA_PREFIX_LSA_PREFIX;
        lsdb_add_node_attr(node, &attr_template);

        if (!ctx->no_sr) {
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(addr, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
            attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_node_prefix.len;
            attr_template.key.prefix.algos[0].sid = node->node_index;
            attr_template.key.prefix.algos[0].flags = LSDB_PREFIX_ALGO_SID;
            attr_template.key.prefix.algo_count = 1;
            attr_template.key.prefix.node_flag = true;

            /* For SR use the Extended-Intra-Area-Router-LSA */
            attr_template.key.ordinal = 1;
            attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
            attr_template.key.attr_cp[1] = OSPF_LSA_E_INTRA_AREA_PREFIX;
            attr_template.key.attr_cp[2] = OSPF_TLV_INTRA_AREA_PREFIX;
            attr_template.key.attr_cp[3] = OSPF_SUBTLV_PREFIX_SID;
            lsdb_add_node_attr(node, &attr_template);
        }

        /* external prefixes */
        ext_per_node = ext_left / nodes_left;
        ext_left -= ext_per_node;
        while (ext_per_node--) {
            /* ipv6 external prefix */
            lsdb_reset_attr_template(&attr_template);
            lspgen_store_addr(ext_addr6, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
            attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_ext_prefix.len;
            attr_template.key.prefix.metric = 100;
            attr_template.key.prefix.tag = ext_per_node;
            attr_template.key.prefix.ext_flag = true;
            attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
            attr_template.key.attr_cp[1] = OSPF_LSA_EXTERNAL6;
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
                memcpy(attr_template.key.link.remote_link_id, link->key.remote_link_id, 4);
                memcpy(attr_template.key.link.local_link_id, link->key.local_link_id, 4);
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
            if (lspgen_load_addr(link->key.remote_node_id, 4) < lspgen_load_addr(link->key.local_node_id, 4)) {
                lspgen_store_addr(addr, attr_template.key.link.remote_link_id, 4);
                lspgen_store_addr(addr+1, attr_template.key.link.local_link_id, 4);
            } else {
                lspgen_store_addr(addr+1, attr_template.key.link.remote_link_id, 4);
                lspgen_store_addr(addr, attr_template.key.link.local_link_id, 4);
            }

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

            /* Generate an IPv6 prefix for each link */
            lsdb_reset_attr_template(&attr_template);

            addr = lspgen_load_addr(ctx->ipv6_link_prefix.address, IPV6_ADDR_LEN);
            inc = lspgen_get_prefix_inc(AF_INET6, ctx->ipv6_link_prefix.len);
            addr += link->link_index * inc;
            lspgen_store_addr(addr, attr_template.key.prefix.ipv6_prefix.address, IPV6_ADDR_LEN);
            attr_template.key.prefix.ipv6_prefix.len = ctx->ipv6_link_prefix.len;
            metric = link->link_metric;
            if (metric > 65535) {
                metric = 65535;
            }
            attr_template.key.prefix.metric = metric;

            attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
            attr_template.key.attr_cp[1] = OSPF_LSA_INTRA_AREA_PREFIX;
            attr_template.key.attr_cp[2] = OSPF_IA_PREFIX_LSA_PREFIX;
            lsdb_add_node_attr(node, &attr_template);
        }

        nodes_left--;
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
    ctx->lsp_buffer_size = ISIS_DEFAULT_LSP_BUFFER_SIZE;

    ctx->link_multiplier = 1;

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

    ctx->ctrl_instance = 1;

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
        LOG(NORMAL, " LSP Buffer size %u\n", ctx->lsp_buffer_size);

    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
        LOG(NORMAL, " Area %s\n", format_ipv4_address(&ctx->topology_id.area));
    }
    LOG(NORMAL, " Sequence 0x%x, lsp-lifetime %u%s\n",
        ctx->sequence, ctx->lsp_lifetime,
        ctx->purge ? ", Purge" : "");

    if (ctx->authentication_key) {
        LOG(NORMAL, " Authentication-key %s, Authentication-type %s\n",
            ctx->authentication_key, val2key(auth_type_names, ctx->authentication_type));
    }
    if (ctx->link_multiplier) {
        LOG(NORMAL, " Link-multiplier %u\n", ctx->link_multiplier);
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
            format_ipv6_prefix(end_prefix6), ctx->num_nodes*2);

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
 * Add a connector string in the form of an
 * iso remote_id xxxx.xxxx.xxxx.xx or
 * ipv4 remote_id:local_ip xxx.xxx.xxx.xxx:yyy.yyy.yyy.yyy
*/
void
lspgen_add_connector(struct lsdb_ctx_ *ctx, char *conn_src)
{
    uint64_t iso_node_id; /* Used for ISO */
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
         * First check if this is a remote-id:local_ip format.
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
        if (!(tok && scan_ipv4_address(tok, &remote_id))) {
            LOG(ERROR, "Invalid connector remote_id %s\n", conn_src);
            return;
        }
        tok = strtok(NULL, ":");
        if (!(tok && scan_ipv4_address(tok, &local_ip))) {
            LOG(ERROR, "Invalid connector local_ip %s\n", tok ? tok : "");
            return;
        }
        /* Addresses are in network byte order. */
        memcpy(ctx->connector[ctx->num_connector].remote_node_id, &remote_id, sizeof(remote_id));
        memcpy(ctx->connector[ctx->num_connector].local_link_id, &local_ip, sizeof(local_ip));

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

            if (isxdigit((unsigned char)conn_src[src])) {
                conn_dst[dst++] = conn_src[src];
            }
        }
        iso_node_id = strtoull(conn_dst, NULL, 16);

        dst_len = strlen(&conn_dst[2]);
        if (dst_len == 0 || dst_len > 16) {
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
    /* Only async-signal-safe operations, the signal is logged after the loop. */
    switch (signum) {
        case SIGINT:
            lspgen_quit_loop();
            break;
        default:
            break;
    }
}

/*
 * Convert the graphviz file into a SVG file. The dot command is executed
 * without shell, so that the file names don't need to be quoted.
 */
static void
lspgen_render_graphviz(struct lsdb_ctx_ *ctx)
{
    char dot_filename[PATH_MAX], svg_filename[PATH_MAX];
    char *dot_argv[] = { "dot", "-Tsvg", dot_filename, "-o", svg_filename, NULL };
    pid_t pid;
    int status;

    if (snprintf(dot_filename, sizeof(dot_filename), "%s.dot", ctx->graphviz_filename) >= (int)sizeof(dot_filename) ||
        snprintf(svg_filename, sizeof(svg_filename), "%s.svg", ctx->graphviz_filename) >= (int)sizeof(svg_filename)) {
        LOG(ERROR, "Graphviz file name %s too long\n", ctx->graphviz_filename);
        return;
    }

    if (posix_spawnp(&pid, "dot", NULL, NULL, dot_argv, environ) == 0 &&
        waitpid(pid, &status, 0) == pid &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        LOG(NORMAL, "Converted graphviz file %s into %s\n", dot_filename, svg_filename);
    } else {
        LOG(ERROR, "Could not convert graphviz file %s into %s\n", dot_filename, svg_filename);
    }
}

/*
 * Parse a numeric option and exit on invalid or out of range values.
 */
static long
lspgen_parse_number(const char *arg, const char *name, int base, long min, long max)
{
    char *end;
    long value;

    errno = 0;
    value = strtol(arg, &end, base);
    if (errno || *end || end == arg || value < min || value > max) {
        LOG(ERROR, "Invalid %s %s (range %ld - %ld)\n", name, arg, min, max);
        exit(EXIT_FAILURE);
    }
    return value;
}

int
main(int argc, char *argv[])
{
    int opt, idx;
    char *end;
    long value;
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
    while ((opt = getopt_long(argc, argv, "vhA:B:D:E:F:Oa:c:C:I:e:f:g:Gl:L:m:M:n:K:N:p:P:q:Qr:s:S:t:T:u:V:w:x:X:yzZ",
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
                if (ctx->protocol_id == PROTO_UNKNOWN) {
                    LOG(ERROR, "Unknown protocol %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
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
                ctx->lsp_lifetime = lspgen_parse_number(optarg, "lsp-lifetime", 10, 1, UINT16_MAX);
                if (ctx->lsp_lifetime < LSP_LIFETIME_MIN) {
                    ctx->lsp_lifetime = LSP_LIFETIME_MIN;
                    LOG(ERROR, "Set lsp-lifetime to min %us\n", ctx->lsp_lifetime);
                }
                break;
            case 'y':
                /* no-sr */
                ctx->no_sr = true;
                break;
            case 'A':
                /* sr-algo */
                if (!lspgen_parse_sr_algo(ctx, optarg)) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'F':
                /* flex-algo */
                if (!lspgen_parse_flex_algo(ctx, optarg)) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'B':
                /* node-msd */
                value = strtol(optarg, &end, 10);
                if (*end || end == optarg || value < 1 || value > 255) {
                    LOG(ERROR, "Invalid node MSD %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                ctx->node_msd = value;
                break;
            case 'O':
                /* elc */
                ctx->elc = true;
                break;
            case 'D':
                /* link-delay */
                if (!lspgen_parse_range(optarg, &ctx->link_delay_min, &ctx->link_delay_max)) {
                    LOG(ERROR, "Invalid link delay %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'E':
                /* te-metric */
                if (!lspgen_parse_range(optarg, &ctx->te_metric_min, &ctx->te_metric_max)) {
                    LOG(ERROR, "Invalid TE metric %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
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
            case 'u':
                ctx->link_multiplier = lspgen_parse_number(optarg, "link-multiplier", 10, 1, INT_MAX);
                if (ctx->link_multiplier > 150) {
                    ctx->link_multiplier = 150;
                    LOG(ERROR, "Set link-multiplier to maximum %u\n", ctx->link_multiplier);
                }
                break;
            case 'c':
                ctx->num_nodes = lspgen_parse_number(optarg, "node-count", 10, 1, INT_MAX);
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
                free(ctx->mrt_filename);
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
                ctx->num_ext = lspgen_parse_number(optarg, "external-count", 10, 0, INT_MAX);
                break;
            case 'K':
                /* authentication-key */
                if (strlen(optarg) > ISIS_AUTH_KEY_MAX_LEN) {
                    LOG(ERROR, "Authentication key longer than %d characters\n", ISIS_AUTH_KEY_MAX_LEN);
                    exit(EXIT_FAILURE);
                }
                free(ctx->authentication_key);
                ctx->authentication_key = strdup(optarg);
                if (ctx->authentication_type == ISIS_AUTH_NONE) {
                    ctx->authentication_type = ISIS_AUTH_SIMPLE;
                }
                break;
            case 'g':
                /* export LSDB as graphviz file and render into a SVG */
                free(ctx->graphviz_filename);
                ctx->graphviz_filename = strdup(optarg);
                break;
            case 'p':
                /* export LSDB as pcap file */
                free(ctx->pcap_filename);
                ctx->pcap_filename = strdup(optarg);
                break;
            case 'f':
                /* export traffic stream file */
                free(ctx->stream_filename);
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
                if (strlen(optarg) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
                    LOG(ERROR, "Control socket path %s too long\n", optarg);
                    exit(EXIT_FAILURE);
                }
                free(ctx->ctrl_socket_path);
                ctx->ctrl_socket_path = strdup(optarg);
                break;
            case 'I':
                /* routing instance-id used by BNG Blaster */
                ctx->ctrl_instance = lspgen_parse_number(optarg, "control-instance", 0, 0, UINT8_MAX);
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

    if ((ctx->sr_algo_count || ctx->fad_count) && ctx->protocol_id != PROTO_ISIS) {
        LOG(ERROR, "SR algorithms are not supported for protocol %s\n", lsdb_format_proto(ctx));
        exit(EXIT_FAILURE);
    }
    if ((ctx->link_delay_max || ctx->te_metric_max || ctx->node_msd || ctx->elc) &&
        ctx->protocol_id != PROTO_ISIS) {
        LOG(ERROR, "Link delay, TE metric, node MSD and ELC are not supported for protocol %s\n",
            lsdb_format_proto(ctx));
        exit(EXIT_FAILURE);
    }
    if (!lspgen_add_flex_algo_to_sr_algo(ctx)) {
        exit(EXIT_FAILURE);
    }
    lspgen_check_srgb_range(ctx);

    /*
     * Read the link-state database from a config file.
     */
    if (ctx->config_read && ctx->config_filename) {
        lspgen_read_config(ctx);
    } else {

        /*
         * Display default options.
         */
        lspgen_log_ctx(ctx);

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
        lsdb_dump_graphviz(ctx);
        lspgen_render_graphviz(ctx);
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
        LOG_NOARG(NORMAL, "Stopped event loop\n");
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
