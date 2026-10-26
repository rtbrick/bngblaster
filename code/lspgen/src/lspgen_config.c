/*
 * LSPGEN - Configuration
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"
#include "lspgen_ospf.h"

/*
 * Write a node or link MSD list, e.g. "msd": [{"type": 1, "value": 10}]
 */
static void
lspgen_write_msd_config(json_t *obj, lsdb_msd_t *msd)
{
    json_t *arr, *msd_obj;
    int idx;

    if (!msd[0].type) {
        return;
    }
    arr = json_array();
    for (idx = 0; idx < LSDB_MAX_MSD && msd[idx].type; idx++) {
        msd_obj = json_object();
        json_object_set_new(msd_obj, "type", json_integer(msd[idx].type));
        json_object_set_new(msd_obj, "value", json_integer(msd[idx].value));
        json_array_append_new(arr, msd_obj);
    }
    json_object_set_new(obj, "msd", arr);
}

/*
 * Read a node or link MSD list, e.g. "msd": [{"type": 1, "value": 10}]
 */
static void
lspgen_read_msd_config(json_t *obj, lsdb_msd_t *msd)
{
    json_t *arr, *msd_obj, *type, *value;
    size_t idx;
    int count = 0;

    arr = json_object_get(obj, "msd");
    if (!arr || !json_is_array(arr)) {
        return;
    }
    json_array_foreach(arr, idx, msd_obj) {
        type = json_object_get(msd_obj, "type");
        value = json_object_get(msd_obj, "value");
        if (!json_is_integer(type) || !json_is_integer(value) ||
            json_integer_value(type) < 1 || json_integer_value(type) > 255 ||
            json_integer_value(value) < 0 || json_integer_value(value) > 255) {
            LOG_NOARG(ERROR, "Ignore invalid MSD\n");
            continue;
        }
        if (count >= LSDB_MAX_MSD) {
            LOG(ERROR, "Ignore MSDs exceeding the maximum of %d\n", LSDB_MAX_MSD);
            return;
        }
        msd[count].type = json_integer_value(type);
        msd[count].value = json_integer_value(value);
        count++;
    }
}

void
lspgen_write_area_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *str;

    str = json_string(format_iso_prefix(&attr->key.area));
    json_array_append_new(arr, str);
}

void
lspgen_write_link_config(lsdb_ctx_t *ctx, json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str;

    obj = json_object();

    switch (ctx->protocol_id) {
    case PROTO_ISIS:
        str = json_string(lsdb_format_node_id(attr->key.link.remote_node_id));
        json_object_set_new(obj, "remote_node_id", str);
        break;
    case PROTO_OSPF2:
    case PROTO_OSPF3:
        str = json_string(format_ipv4_address((uint32_t*)&(attr->key.link.remote_node_id)));
        json_object_set_new(obj, "remote_node_id", str);
        str = json_string(format_ipv4_address((uint32_t*)&(attr->key.link.local_link_id)));
        json_object_set_new(obj, "local_link_id", str);

        /* Remote link ID is optional */
        if (strcmp(format_ipv4_address((uint32_t*)&(attr->key.link.remote_link_id)), "0.0.0.0") != 0) {
            str = json_string(format_ipv4_address((uint32_t*)&(attr->key.link.remote_link_id)));
            json_object_set_new(obj, "remote_link_id", str);
        }
        break;
    default:
        LOG_NOARG(ERROR, "Unknown protocol\n");
        return;
    }

    json_object_set_new(obj, "metric", json_integer(attr->key.link.metric));
    if (attr->key.link.asla) {
        /* Application-specific link attributes for Flex-Algo */
        json_object_set_new(obj, "te_metric", json_integer(attr->key.link.te_metric));
        json_object_set_new(obj, "min_delay", json_integer(attr->key.link.min_delay));
        json_object_set_new(obj, "max_delay", json_integer(attr->key.link.max_delay));
        if (attr->key.link.admin_group) {
            json_object_set_new(obj, "admin_group", json_integer(attr->key.link.admin_group));
        }
    }
    lspgen_write_msd_config(obj, attr->key.link.msd);
    json_array_append_new(arr, obj);
}

void
lspgen_write_cap_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str, *algo_arr;
    int idx;

    obj = json_object();
    str = json_string(format_ipv4_address((uint32_t*)attr->key.cap.router_id));
    json_object_set_new(obj, "router_id", str);
    if (attr->key.cap.s_flag) {
        json_object_set_new(obj, "s_flag", json_boolean(1));
    }
    if (attr->key.cap.d_flag) {
        json_object_set_new(obj, "d_flag", json_boolean(1));
    }
    if (attr->key.cap.mpls_ipv4_flag) {
        json_object_set_new(obj, "mpls_ipv4_flag", json_boolean(1));
    }
    if (attr->key.cap.mpls_ipv6_flag) {
        json_object_set_new(obj, "mpls_ipv6_flag", json_boolean(1));
    }
    json_object_set_new(obj, "srgb_base", json_integer(attr->key.cap.srgb_base));
    json_object_set_new(obj, "srgb_range", json_integer(attr->key.cap.srgb_range));
    if (attr->key.cap.sr_algo_len) {
        algo_arr = json_array();
        for (idx = 0; idx < attr->key.cap.sr_algo_len; idx++) {
            json_array_append_new(algo_arr, json_integer(attr->key.cap.sr_algo[idx]));
        }
        json_object_set_new(obj, "sr_algo_list", algo_arr);
    }
    lspgen_write_msd_config(obj, attr->key.cap.msd);
    json_array_append_new(arr, obj);
}

/*
 * Flex-Algo definition metric type / name translation table.
 */
struct keyval_ fad_metric_names[] = {
    { LSDB_FAD_METRIC_IGP,       "igp" },
    { LSDB_FAD_METRIC_MIN_DELAY, "min-delay" },
    { LSDB_FAD_METRIC_TE,        "te" },
    { 0, NULL}
};

/*
 * Scan a Flex-Algo definition metric type name.
 */
bool
lspgen_scan_fad_metric_type(const char *name, uint8_t *metric_type)
{
    struct keyval_ *ptr;

    for (ptr = fad_metric_names; ptr->key; ptr++) {
        if (strcmp(ptr->key, name) == 0) {
            *metric_type = ptr->val;
            return true;
        }
    }
    return false;
}

void
lspgen_write_fad_config(json_t *arr, lsdb_attr_t *attr)
{
    lsdb_attr_fad_t *fad = &attr->key.fad;
    json_t *obj;

    obj = json_object();
    json_object_set_new(obj, "router_id", json_string(format_ipv4_address((uint32_t*)fad->router_id)));
    json_object_set_new(obj, "algo", json_integer(fad->algo));
    json_object_set_new(obj, "metric_type", json_string(val2key(fad_metric_names, fad->metric_type)));
    if (fad->calc_type) {
        json_object_set_new(obj, "calc_type", json_integer(fad->calc_type));
    }
    json_object_set_new(obj, "priority", json_integer(fad->priority));
    if (fad->m_flag) {
        json_object_set_new(obj, "m_flag", json_boolean(1));
    }
    if (fad->exclude_any) {
        json_object_set_new(obj, "exclude_any", json_integer(fad->exclude_any));
    }
    if (fad->include_any) {
        json_object_set_new(obj, "include_any", json_integer(fad->include_any));
    }
    if (fad->include_all) {
        json_object_set_new(obj, "include_all", json_integer(fad->include_all));
    }
    json_array_append_new(arr, obj);
}

/*
 * Common function shared between ipv4_prefix,
 * ipv6_prefix and label_binding writers.
 */
void
lspgen_write_common_prefix_config(json_t *obj, lsdb_attr_t *attr)
{
    lsdb_prefix_algo_t *entry;
    json_t *sid_arr = NULL, *fapm_arr = NULL, *sid_obj, *fapm_obj, *flag_arr;
    int idx;

    json_object_set_new(obj, "metric", json_integer(attr->key.prefix.metric));
    entry = &attr->key.prefix.algos[0];
    if (attr->key.prefix.algo_count == 1 && entry->algo == 0 &&
        entry->flags == LSDB_PREFIX_ALGO_SID) {
        json_object_set_new(obj, "segment_id", json_integer(entry->sid));
        entry = NULL; /* short form */
    }
    for (idx = 0; entry && idx < attr->key.prefix.algo_count; idx++) {
        entry = &attr->key.prefix.algos[idx];
        if (LSDB_PREFIX_HAS_SID(entry)) {
            if (!sid_arr) {
                sid_arr = json_array();
                json_object_set_new(obj, "segment_ids", sid_arr);
            }
            sid_obj = json_object();
            json_object_set_new(sid_obj, "index", json_integer(entry->sid));
            json_object_set_new(sid_obj, "algo", json_integer(entry->algo));
            if (entry->flags & LSDB_PREFIX_SID_FLAG_MASK) {
                flag_arr = json_array();
                if (entry->flags & LSDB_PREFIX_SID_FLAG_NO_PHP) {
                    json_array_append_new(flag_arr, json_string("no-php"));
                }
                if (entry->flags & LSDB_PREFIX_SID_FLAG_EXP_NULL) {
                    json_array_append_new(flag_arr, json_string("explicit-null"));
                }
                if (entry->flags & LSDB_PREFIX_SID_FLAG_VALUE) {
                    json_array_append_new(flag_arr, json_string("value"));
                }
                if (entry->flags & LSDB_PREFIX_SID_FLAG_LOCAL) {
                    json_array_append_new(flag_arr, json_string("local"));
                }
                json_object_set_new(sid_obj, "flags", flag_arr);
            }
            json_array_append_new(sid_arr, sid_obj);
        }
        if (entry->flags & LSDB_PREFIX_ALGO_FAPM) {
            if (!fapm_arr) {
                fapm_arr = json_array();
                json_object_set_new(obj, "flex_algo_metrics", fapm_arr);
            }
            fapm_obj = json_object();
            json_object_set_new(fapm_obj, "algo", json_integer(entry->algo));
            json_object_set_new(fapm_obj, "metric", json_integer(entry->metric));
            json_array_append_new(fapm_arr, fapm_obj);
        }
    }
    if (attr->key.prefix.adv_tag) {
        json_object_set_new(obj, "tag", json_integer(attr->key.prefix.tag));
    }
    if (attr->key.prefix.adv_range) {
        json_object_set_new(obj, "range", json_integer(attr->key.prefix.range));
    }
    if (attr->key.prefix.node_flag) {
        json_object_set_new(obj, "node_flag", json_boolean(1));
    }
    if (attr->key.prefix.ext_flag) {
        json_object_set_new(obj, "external_flag", json_boolean(1));
    }
    if (attr->key.prefix.updown_flag) {
        json_object_set_new(obj, "updown_flag", json_boolean(1));
    }
    if (attr->key.prefix.s_flag) {
        json_object_set_new(obj, "s_flag", json_boolean(1));
    }
    if (attr->key.prefix.elc_flag) {
        json_object_set_new(obj, "elc_flag", json_boolean(1));
    }
}

void
lspgen_write_ipv4_addr_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *str;

    str = json_string(format_ipv4_address((uint32_t*)attr->key.ipv4_addr));
    json_array_append_new(arr, str);
}

/*
 * IS-IS NLPID / name translation table.
 */
struct keyval_ isis_nlpid_names[] = {
    { NLPID_IPV4, "ipv4" },
    { NLPID_IPV6, "ipv6" },
    { 0, NULL}
};

void
lspgen_write_protocol_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *str;

    str = json_string(val2key(isis_nlpid_names, attr->key.protocol));
    json_array_append_new(arr, str);
}

void
lspgen_write_ipv4_prefix_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str;

    obj = json_object();
    str = json_string(format_ipv4_prefix(&attr->key.prefix.ipv4_prefix));
    json_object_set_new(obj, "ipv4_prefix", str);
    lspgen_write_common_prefix_config(obj, attr);
    json_array_append_new(arr, obj);
}

void
lspgen_write_ipv6_addr_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *str;

    str = json_string(format_ipv6_address((ipv6addr_t*)attr->key.ipv6_addr));
    json_array_append_new(arr, str);
}

void
lspgen_write_ipv6_prefix_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str;

    obj = json_object();
    str = json_string(format_ipv6_prefix(&attr->key.prefix.ipv6_prefix));
    json_object_set_new(obj, "ipv6_prefix", str);
    lspgen_write_common_prefix_config(obj, attr);
    json_array_append_new(arr, obj);
}

void
lspgen_write_label_binding_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str;

    obj = json_object();
    if (attr->key.prefix.family_flag) {
        str = json_string(format_ipv6_prefix(&attr->key.prefix.ipv6_prefix));
        json_object_set_new(obj, "ipv6_prefix", str);
    } else {
        str = json_string(format_ipv4_prefix(&attr->key.prefix.ipv4_prefix));
        json_object_set_new(obj, "ipv4_prefix", str);
    }
    lspgen_write_common_prefix_config(obj, attr);
    json_array_append_new(arr, obj);
}

void
lspgen_write_node_common_config(lsdb_ctx_t *ctx, lsdb_node_t *node, json_t *node_obj)
{
    json_t *str;
    char seq[12];

    switch (ctx->protocol_id) {
    case PROTO_ISIS:
        str = json_string(lsdb_format_node_id(node->key.node_id));
        json_object_set_new(node_obj, "node_id", str);

        if (node->overload) {
            json_object_set_new(node_obj, "overload", json_boolean(1));
        }
        if (node->attach) {
            json_object_set_new(node_obj, "attach", json_boolean(1));
        }
        json_object_set_new(node_obj, "lsp_buffer_size", json_integer(ISIS_DEFAULT_LSP_BUFFER_SIZE));
        break;
    case PROTO_OSPF2:
    case PROTO_OSPF3: /* fall through */
        str = json_string(lsdb_format_node_no_name(node));
        json_object_set_new(node_obj, "node_id", str);
        break;
    default:
        LOG_NOARG(ERROR, "Unknown protocol\n");
        return;
    }

    json_object_set_new(node_obj, "hostname", json_string(node->node_name));
    if (node->sequence) {
        snprintf(seq, sizeof(seq), "0x%08x", node->sequence);
        json_object_set_new(node_obj, "sequence", json_string(seq));
    }

    if (node->lsp_lifetime) {
        json_object_set_new(node_obj, "lsp_lifetime", json_integer(node->lsp_lifetime));
    }

    /*
     * Flags
     */
    if (node->is_root) {
        json_object_set_new(node_obj, "is_root", json_boolean(node->is_root));
    }
    if (node->is_pseudonode) {
        json_object_set_new(node_obj, "is_pseudonode", json_boolean(node->is_pseudonode));
    }
    if (node->is_local_pseudonode) {
        json_object_set_new(node_obj, "is_local_pseudonode", json_boolean(node->is_local_pseudonode));
    }
    if (node->is_direct_neighbor) {
        json_object_set_new(node_obj, "is_direct_neighbor", json_boolean(node->is_direct_neighbor));
    }
}

void
lspgen_write_node_ospf2_config(lsdb_ctx_t *ctx, lsdb_node_t *node, json_t *level_arr)
{
    struct lsdb_attr_ *attr;
    dict_itor *itor;
    json_t *node_obj;
    json_t *ipv4_prefix_arr = NULL;
    json_t *nbr_arr = NULL;
    json_t *cap_arr = NULL;

    /* Walk the node attributes. */
    if (!node->attr_dict) {
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }
    itor = dict_itor_new(node->attr_dict);
    if (!itor) {
        return;
    }

    /* Node attribute DB empty? */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }

    node_obj = json_object();
    lspgen_write_node_common_config(ctx, node, node_obj);

    do {
        attr = *dict_itor_datum(itor);

        /* Level 0 */
        switch (attr->key.attr_cp[0]) {
        case 0: /* fall through */
        case OSPF_MSG_LSUPDATE:
            break;
        default:
            LOG(ERROR, "No ospf2 json encoder for L0 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[0]),
                attr->key.attr_cp[0]);
            break;
        }

        /* Level 1 */
        switch (attr->key.attr_cp[1]) {
        case 0: /* fall through */
        case OSPF_LSA_ROUTER:
        case OSPF_LSA_OPAQUE_AREA_RI:
        case OSPF_LSA_OPAQUE_AREA_EP:
            break;
        case OSPF_LSA_EXTERNAL:
            if (!ipv4_prefix_arr) {
                ipv4_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv4_prefix_list", ipv4_prefix_arr);
            }
            lspgen_write_ipv4_prefix_config(ipv4_prefix_arr, attr);
            break;
        default:
            LOG(ERROR, "No ospf2 json encoder for L1 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[1]),
                attr->key.attr_cp[1]);
            break;
        }

        /* Level 2 */
        switch (attr->key.attr_cp[2]) {
        case 0: /* fall through */
        case OSPF_TLV_HOSTNAME:
        case OSPF_TLV_EXTENDED_PREFIX:
            break;
        case OSPF_ROUTER_LSA_LINK_PTP:
            if (!nbr_arr) {
                nbr_arr = json_array();
                json_object_set_new(node_obj, "neighbor_list", nbr_arr);
            }
            lspgen_write_link_config(ctx, nbr_arr, attr);
            break;
        case OSPF_ROUTER_LSA_LINK_STUB:

            /* Skip node prefixes, they are encoded also in Extended Prefixes */
            if (attr->key.prefix.node_flag && !ctx->no_sr) {
                break;
            }

            if (!ipv4_prefix_arr) {
                ipv4_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv4_prefix_list", ipv4_prefix_arr);
            }
            lspgen_write_ipv4_prefix_config(ipv4_prefix_arr, attr);
            break;
        case OSPF_TLV_SID_LABEL_RANGE:
            if (!cap_arr) {
                cap_arr = json_array();
                json_object_set_new(node_obj, "capability_list", cap_arr);
            }
            lspgen_write_cap_config(cap_arr, attr);
            break;
        default:
            LOG(ERROR, "No ospf2 json encoder for L2 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[2]),
                attr->key.attr_cp[2]);
            break;
        }

        /* Level 3 */
        switch (attr->key.attr_cp[3]) {
        case 0:
            break;
        case OSPF_SUBTLV_PREFIX_SID:
            if (!ipv4_prefix_arr) {
                ipv4_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv4_prefix_list", ipv4_prefix_arr);
            }
            lspgen_write_ipv4_prefix_config(ipv4_prefix_arr, attr);
            break;
        default:
            LOG(ERROR, "No ospf2 json encoder for L3 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[3]),
                attr->key.attr_cp[3]);
            break;
        }

    } while (dict_itor_next(itor));

    json_array_append_new(level_arr, node_obj);

    dict_itor_free(itor);
}

void
lspgen_write_node_ospf3_config(lsdb_ctx_t *ctx, lsdb_node_t *node, json_t *level_arr)
{
    struct lsdb_attr_ *attr;
    dict_itor *itor;
    json_t *node_obj;
    json_t *ipv6_prefix_arr = NULL;
    json_t *nbr_arr = NULL;
    json_t *cap_arr = NULL;

    /* Walk the node attributes. */
    if (!node->attr_dict) {
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }
    itor = dict_itor_new(node->attr_dict);
    if (!itor) {
        return;
    }

    /* Node attribute DB empty? */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }

    node_obj = json_object();
    lspgen_write_node_common_config(ctx, node, node_obj);

    do {
        attr = *dict_itor_datum(itor);

        /* Level 0 */
        switch (attr->key.attr_cp[0]) {
        case 0: /* fall through */
        case OSPF_MSG_LSUPDATE:
            break;
        default:
            LOG(ERROR, "No ospf3 json encoder for L0 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[0]),
                attr->key.attr_cp[0]);
            break;
        }

        /* Level 1 */
        switch (attr->key.attr_cp[1]) {
        case 0: /* fall through */
        case OSPF_LSA_ROUTER:
        case OSPF_LSA_OPAQUE_AREA_RI:
        case OSPF_LSA_INTRA_AREA_PREFIX:
        case OSPF_LSA_E_INTRA_AREA_PREFIX:
            break;
        case OSPF_LSA_EXTERNAL6:
            if (!ipv6_prefix_arr) {
                ipv6_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv6_prefix_list", ipv6_prefix_arr);
            }
            lspgen_write_ipv6_prefix_config(ipv6_prefix_arr, attr);
            break;
        default:
            LOG(ERROR, "No ospf3 json encoder for L1 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[1]),
                attr->key.attr_cp[1]);
            break;
        }

        /* Level 2 */
        switch (attr->key.attr_cp[2]) {
        case 0: /* fall through */
        case OSPF_TLV_HOSTNAME:
        case OSPF_TLV_INTRA_AREA_PREFIX:
            break;
        case OSPF_ROUTER_LSA_LINK_PTP:
            if (!nbr_arr) {
                nbr_arr = json_array();
                json_object_set_new(node_obj, "neighbor_list", nbr_arr);
            }
            lspgen_write_link_config(ctx, nbr_arr, attr);
            break;
        case OSPF_IA_PREFIX_LSA_PREFIX:

            /* Skip node prefixes, they are encoded also in Extended Intra-Area Prefixes */
            if (attr->key.prefix.node_flag && !ctx->no_sr) {
                break;
            }

            if (!ipv6_prefix_arr) {
                ipv6_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv6_prefix_list", ipv6_prefix_arr);
            }
            lspgen_write_ipv6_prefix_config(ipv6_prefix_arr, attr);
            break;
        case OSPF_TLV_SID_LABEL_RANGE:
            if (!cap_arr) {
                cap_arr = json_array();
                json_object_set_new(node_obj, "capability_list", cap_arr);
            }
            lspgen_write_cap_config(cap_arr, attr);
            break;
        default:
            LOG(ERROR, "No ospf3 json encoder for L2 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[2]),
                attr->key.attr_cp[2]);
            break;
        }

        /* Level 3 */
        switch (attr->key.attr_cp[3]) {
        case 0:
            break;
        case OSPF_SUBTLV_PREFIX_SID:
            if (!ipv6_prefix_arr) {
                ipv6_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv6_prefix_list", ipv6_prefix_arr);
            }
            lspgen_write_ipv6_prefix_config(ipv6_prefix_arr, attr);
            break;
        default:
            LOG(ERROR, "No ospf3 json encoder for L3 attr %s (%d)\n",
                val2key(ospf_attr_names, attr->key.attr_cp[3]),
                attr->key.attr_cp[3]);
            break;
        }

    } while (dict_itor_next(itor));

    json_array_append_new(level_arr, node_obj);

    dict_itor_free(itor);
}

void
lspgen_write_node_isis_config(lsdb_ctx_t *ctx, lsdb_node_t *node, json_t *level_arr)
{
    struct lsdb_attr_ *attr;
    dict_itor *itor;
    json_t *node_obj;
    json_t *ipv4_addr_arr = NULL;
    json_t *ipv6_addr_arr = NULL;
    json_t *ipv4_prefix_arr = NULL;
    json_t *ipv6_prefix_arr = NULL;
    json_t *area_arr = NULL;
    json_t *nbr_arr = NULL;
    json_t *protocol_arr = NULL;
    json_t *cap_arr = NULL;
    json_t *fad_arr = NULL;
    json_t *binding_arr = NULL;

    /* Walk the node attributes. */
    if (!node->attr_dict) {
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }
    itor = dict_itor_new(node->attr_dict);
    if (!itor) {
        return;
    }

    /* Node attribute DB empty? */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }

    node_obj = json_object();
    lspgen_write_node_common_config(ctx, node, node_obj);

    do {
        attr = *dict_itor_datum(itor);

        switch (attr->key.attr_type) {
        case ISIS_TLV_AREA:
            if (!area_arr) {
                area_arr = json_array();
                json_object_set_new(node_obj, "area_list", area_arr);
            }
            lspgen_write_area_config(area_arr, attr);
            break;
        case ISIS_TLV_PROTOCOLS:
            if (!protocol_arr) {
                protocol_arr = json_array();
                json_object_set_new(node_obj, "protocol_list", protocol_arr);
            }
            lspgen_write_protocol_config(protocol_arr, attr);
            break;
        case ISIS_TLV_HOSTNAME: /* already generated above */
            break;
        case ISIS_TLV_LSP_BUFFER_SIZE: /* already generated above */
            break;
        case ISIS_TLV_CAP:
            if (attr->key.attr_cp[0] == ISIS_SUBTLV_CAP_FAD) {
                if (!fad_arr) {
                    fad_arr = json_array();
                    json_object_set_new(node_obj, "flex_algo_list", fad_arr);
                }
                lspgen_write_fad_config(fad_arr, attr);
                break;
            }
            if (!cap_arr) {
                cap_arr = json_array();
                json_object_set_new(node_obj, "capability_list", cap_arr);
            }
            lspgen_write_cap_config(cap_arr, attr);
            break;
        case ISIS_TLV_EXTD_IS_REACH:
            if (!nbr_arr) {
                nbr_arr = json_array();
                json_object_set_new(node_obj, "neighbor_list", nbr_arr);
            }
            lspgen_write_link_config(ctx, nbr_arr, attr);
            break;
        case ISIS_TLV_IPV4_ADDR:
            if (!ipv4_addr_arr) {
                ipv4_addr_arr = json_array();
                json_object_set_new(node_obj, "ipv4_address_list", ipv4_addr_arr);
            }
            lspgen_write_ipv4_addr_config(ipv4_addr_arr, attr);
            break;
        case ISIS_TLV_IPV6_ADDR:
            if (!ipv6_addr_arr) {
                ipv6_addr_arr = json_array();
                json_object_set_new(node_obj, "ipv6_address_list", ipv6_addr_arr);
            }
            lspgen_write_ipv6_addr_config(ipv6_addr_arr, attr);
            break;
        case ISIS_TLV_EXTD_IPV4_REACH:
            if (!ipv4_prefix_arr) {
                ipv4_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv4_prefix_list", ipv4_prefix_arr);
            }
            lspgen_write_ipv4_prefix_config(ipv4_prefix_arr, attr);
            break;
        case ISIS_TLV_EXTD_IPV6_REACH:
            if (!ipv6_prefix_arr) {
                ipv6_prefix_arr = json_array();
                json_object_set_new(node_obj, "ipv6_prefix_list", ipv6_prefix_arr);
            }
            lspgen_write_ipv6_prefix_config(ipv6_prefix_arr, attr);
            break;
        case ISIS_TLV_BINDING:
            if (!binding_arr) {
                binding_arr = json_array();
                json_object_set_new(node_obj, "label_binding_list", binding_arr);
            }
            lspgen_write_label_binding_config(binding_arr, attr);
            break;
        default:
            LOG(ERROR, "No isis json encoder for attr %d\n", attr->key.attr_type);
            break;
        }
    } while (dict_itor_next(itor));

    json_array_append_new(level_arr, node_obj);

    dict_itor_free(itor);
}

/*
 * IS-IS Level / name translation table.
 */
struct keyval_ isis_level_names[] = {
    { 1, "level1" },
    { 2, "level2" },
    { 0, NULL}
};

void
lspgen_write_config(lsdb_ctx_t *ctx)
{
    struct lsdb_node_ *node;
    dict_itor *itor;
    json_t *root_obj, *arr;
    int res;
    char ospf_area[sizeof("area255.255.255.255")];

    /* Walk the node DB. */
    itor = dict_itor_new(ctx->node_dict);
    if (!itor) {
        return;
    }

    /* Node DB empty? */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG_NOARG(ERROR, "Empty LSDB.\n");
        return;
    }

    ctx->config_file = fopen(ctx->config_filename, "w");
    if (!ctx->config_file) {
        LOG(ERROR, "Error opening config file %s\n", ctx->config_filename);
        dict_itor_free(itor);
        return;
    }

    root_obj = json_object();
    json_object_set_new(root_obj, "instance", json_string(ctx->instance_name));
    json_object_set_new(root_obj, "protocol", json_string(lsdb_format_proto(ctx)));
    json_object_set_new(root_obj, "lsp_lifetime", json_integer(ctx->lsp_lifetime));
    arr = json_array();

    switch (ctx->protocol_id) {
    case PROTO_ISIS:
        json_object_set_new(root_obj, val2key(isis_level_names, ctx->topology_id.level), arr);
        break;
    case PROTO_OSPF2: /* fall through */
    case PROTO_OSPF3:
        snprintf(ospf_area, sizeof(ospf_area), "area%s", format_ipv4_address(&ctx->topology_id.area));
        json_object_set_new(root_obj, ospf_area, arr);
        break;
    default:
        LOG_NOARG(ERROR, "Unknown protocol\n");
        goto done;
    }

    do {
        node = *dict_itor_datum(itor);

        switch (ctx->protocol_id) {
        case PROTO_ISIS:
            lspgen_write_node_isis_config(ctx, node, arr);
            break;
        case PROTO_OSPF2:
            lspgen_write_node_ospf2_config(ctx, node, arr);
            break;
        case PROTO_OSPF3:
            lspgen_write_node_ospf3_config(ctx, node, arr);
            break;
        default:
            LOG_NOARG(ERROR, "Unknown protocol\n");
        }

    } while (dict_itor_next(itor));
    dict_itor_free(itor);

    res = json_dumpf(root_obj, ctx->config_file, JSON_INDENT(2));
    if (res == -1) {
        LOG(ERROR, "Error writing config file %s\n", ctx->config_filename);
    }

    /* Done */
done:
    json_decref(root_obj);
    fclose(ctx->config_file);
    ctx->config_file = NULL;
}

/*
 * Read an ISO Area from a config and add it as an node attribute.
 */
void
lspgen_read_iso_area_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_attr_ attr_template;
    const char *s;

    if (!json_is_string(obj)) {
        return;
    }

    s = json_string_value(obj);

    lsdb_reset_attr_template(&attr_template);
    scan_iso_prefix(s, &attr_template.key.area);
    attr_template.key.ordinal = 1;
    attr_template.key.attr_type = ISIS_TLV_AREA;
    lsdb_add_node_attr(node, &attr_template);
}

void
lspgen_read_protocol_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_attr_ attr_template;
    const char *s;

    if (!json_is_string(obj)) {
        return;
    }

    s = json_string_value(obj);

    lsdb_reset_attr_template(&attr_template);
    attr_template.key.protocol = key2val(isis_nlpid_names, s);
    attr_template.key.ordinal = 1;
    attr_template.key.attr_type = ISIS_TLV_PROTOCOLS;
    lsdb_add_node_attr(node, &attr_template);
}

void
lspgen_read_ipv4_addr_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_attr_ attr_template;
    const char *s;

    if (!json_is_string(obj)) {
        return;
    }

    s = json_string_value(obj);
    lsdb_reset_attr_template(&attr_template);
    if (!inet_pton(AF_INET, s, &attr_template.key.ipv4_addr)) {
        LOG(ERROR, "Error reading bogus ipv4 address %s\n", s);
        return;
    }
    attr_template.key.ordinal = 1;
    attr_template.key.attr_type = ISIS_TLV_IPV4_ADDR;
    lsdb_add_node_attr(node, &attr_template);
}

void
lspgen_read_ipv6_addr_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_attr_ attr_template;
    const char *s;

    if (!json_is_string(obj)) {
        return;
    }

    s = json_string_value(obj);
    lsdb_reset_attr_template(&attr_template);
    if (!inet_pton(AF_INET6, s, &attr_template.key.ipv6_addr)) {
        LOG(ERROR, "Error reading bogus ipv6 address %s\n", s);
        return;
    }
    attr_template.key.ordinal = 1;
    attr_template.key.attr_type = ISIS_TLV_IPV6_ADDR;
    lsdb_add_node_attr(node, &attr_template);
}

/*
 * Common function shared between ipv4_prefix,
 * ipv6_prefix and label_binding readers.
 */
/*
 * Translation table for Prefix-SID flags.
 */
struct keyval_ prefix_sid_flag_names[] = {
    { LSDB_PREFIX_SID_FLAG_NO_PHP,   "no-php" },
    { LSDB_PREFIX_SID_FLAG_EXP_NULL, "explicit-null" },
    { LSDB_PREFIX_SID_FLAG_VALUE,    "value" },
    { LSDB_PREFIX_SID_FLAG_LOCAL,    "local" },
    { 0, NULL}
};

/*
 * Return the prefix entry of an algorithm, a new entry is added if required.
 */
static lsdb_prefix_algo_t *
lspgen_get_prefix_algo(lsdb_attr_t *attr, uint8_t algo)
{
    lsdb_prefix_algo_t *entry;
    int idx;

    for (idx = 0; idx < attr->key.prefix.algo_count; idx++) {
        entry = &attr->key.prefix.algos[idx];
        if (entry->algo == algo) {
            return entry;
        }
    }
    if (attr->key.prefix.algo_count >= LSDB_MAX_PREFIX_ALGO) {
        LOG(ERROR, "Ignore algorithm %u exceeding the maximum of %d algorithms per prefix\n",
            algo, LSDB_MAX_PREFIX_ALGO);
        return NULL;
    }
    entry = &attr->key.prefix.algos[attr->key.prefix.algo_count++];
    entry->algo = algo;
    return entry;
}

/*
 * Read the list of Prefix-SIDs, e.g.
 * "segment_ids": [ {"index": 1, "algo": 0}, {"index": 101, "algo": 128, "flags": ["no-php"]} ]
 */
static void
lspgen_read_prefix_sid_config(lsdb_attr_t *attr, json_t *arr)
{
    lsdb_prefix_algo_t *entry;
    json_t *sid_obj, *value, *flag;
    size_t idx, flag_idx;
    const char *s;
    uint32_t sid;
    uint8_t algo;
    int flag_value;

    if (!arr || !json_is_array(arr)) {
        return;
    }
    json_array_foreach(arr, idx, sid_obj) {
        value = json_object_get(sid_obj, "index");
        if (!value || !json_is_integer(value)) {
            LOG_NOARG(ERROR, "Ignore Prefix-SID without index\n");
            continue;
        }
        sid = json_integer_value(value);
        algo = 0;
        value = json_object_get(sid_obj, "algo");
        if (value && json_is_integer(value)) {
            algo = json_integer_value(value);
        }
        entry = lspgen_get_prefix_algo(attr, algo);
        if (!entry) {
            continue;
        }
        entry->sid = sid;
        entry->flags |= LSDB_PREFIX_ALGO_SID;
        value = json_object_get(sid_obj, "flags");
        if (value && json_is_array(value)) {
            json_array_foreach(value, flag_idx, flag) {
                s = json_string_value(flag);
                flag_value = s ? key2val(prefix_sid_flag_names, s) : 0;
                if (!flag_value) {
                    LOG(ERROR, "Ignore unknown Prefix-SID flag %s\n", s ? s : "");
                    continue;
                }
                entry->flags |= flag_value;
            }
        }
    }
}

/*
 * Read the list of Flex-Algo prefix metrics, e.g.
 * "flex_algo_metrics": [ {"algo": 128, "metric": 20} ]
 */
static void
lspgen_read_prefix_fapm_config(lsdb_attr_t *attr, json_t *arr)
{
    lsdb_prefix_algo_t *entry;
    json_t *fapm_obj, *algo, *metric;
    size_t idx;

    if (!arr || !json_is_array(arr)) {
        return;
    }
    json_array_foreach(arr, idx, fapm_obj) {
        algo = json_object_get(fapm_obj, "algo");
        metric = json_object_get(fapm_obj, "metric");
        if (!json_is_integer(algo) || !json_is_integer(metric) ||
            json_integer_value(algo) < 128 || json_integer_value(algo) > 255) {
            LOG_NOARG(ERROR, "Ignore invalid Flex-Algo prefix metric\n");
            continue;
        }
        entry = lspgen_get_prefix_algo(attr, json_integer_value(algo));
        if (!entry) {
            continue;
        }
        entry->metric = json_integer_value(metric);
        entry->flags |= LSDB_PREFIX_ALGO_FAPM;
    }
}

void
lspgen_read_common_prefix_config(lsdb_attr_t *attr, json_t *obj)
{
    lsdb_prefix_algo_t *entry;
    json_t *value;

    value = json_object_get(obj, "metric");
    if (value && json_is_integer(value)) {
        attr->key.prefix.metric = json_integer_value(value);
    }
    value = json_object_get(obj, "segment_id");
    if (value && json_is_integer(value)) {
        entry = lspgen_get_prefix_algo(attr, 0);
        entry->sid = json_integer_value(value);
        entry->flags |= LSDB_PREFIX_ALGO_SID;
    }
    lspgen_read_prefix_sid_config(attr, json_object_get(obj, "segment_ids"));
    lspgen_read_prefix_fapm_config(attr, json_object_get(obj, "flex_algo_metrics"));
    value = json_object_get(obj, "tag");
    if (value && json_is_integer(value)) {
        attr->key.prefix.tag = json_integer_value(value);
        attr->key.prefix.adv_tag = true;
    }
    value = json_object_get(obj, "range"); /* binding TLV */
    if (value && json_is_integer(value)) {
        attr->key.prefix.range = json_integer_value(value);
        attr->key.prefix.adv_range = true;
    }
    value = json_object_get(obj, "node_flag");
    if (value && json_is_boolean(value)) {
        attr->key.prefix.node_flag = json_boolean_value(value);
        attr->key.ordinal = 1;
    }
    value = json_object_get(obj, "external_flag");
    if (value && json_is_boolean(value)) {
        attr->key.prefix.ext_flag = json_boolean_value(value);
    }
    value = json_object_get(obj, "updown_flag");
    if (value && json_is_boolean(value)) {
        attr->key.prefix.updown_flag = json_boolean_value(value);
    }
    value = json_object_get(obj, "s_flag"); /* binding TLV */
    if (value && json_is_boolean(value)) {
        attr->key.prefix.s_flag = json_boolean_value(value);
    }
    value = json_object_get(obj, "small_metrics");
    if (value && json_is_boolean(value)) {
        attr->key.prefix.small_metrics = json_boolean_value(value);
    }
    value = json_object_get(obj, "elc_flag");
    if (value && json_is_boolean(value)) {
        attr->key.prefix.elc_flag = json_boolean_value(value);
    }
}

void
lspgen_read_ipv4_prefix_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_ctx_ *ctx;
    struct lsdb_attr_ attr_template;
    struct lsdb_attr_ sid_attr_template;
    char *s;

    ctx = node->ctx;

    lsdb_reset_attr_template(&attr_template);
    if (json_unpack(obj, "{s:s}", "ipv4_prefix", &s) == 0) {
        scan_ipv4_prefix(s, &attr_template.key.prefix.ipv4_prefix);

        lspgen_read_common_prefix_config(&attr_template, obj);

        if (ctx->protocol_id == PROTO_ISIS) {

            /*
             * IS-IS TLV type depends on small-metrics and external flag.
             */
            if (attr_template.key.prefix.small_metrics) {
                if (attr_template.key.prefix.ext_flag) {
                    attr_template.key.attr_type = ISIS_TLV_EXT_IPV4_REACH;
                } else {
                    attr_template.key.attr_type = ISIS_TLV_INT_IPV4_REACH;
                }
            } else {
                attr_template.key.attr_type = ISIS_TLV_EXTD_IPV4_REACH;
            }
        } else if (ctx->protocol_id == PROTO_OSPF2) {

            if (attr_template.key.prefix.ext_flag) {

                /* OSPF external */
                attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
                attr_template.key.attr_cp[1] = OSPF_LSA_EXTERNAL;
                attr_template.key.start_tlv = true;
            } else {

                if (LSDB_PREFIX_HAS_SID(&attr_template.key.prefix.algos[0])) {

                    /* OSPF loopback with prefix sid, advertised as stub link
                     * in the router-LSA and in the extended prefix LSA */
                    memcpy(&sid_attr_template, &attr_template, sizeof(sid_attr_template));
                    sid_attr_template.key.ordinal = 1;
                    sid_attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
                    sid_attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_EP;
                    sid_attr_template.key.attr_cp[2] = OSPF_TLV_EXTENDED_PREFIX;
                    sid_attr_template.key.attr_cp[3] = OSPF_SUBTLV_PREFIX_SID;
                    lsdb_add_node_attr(node, &sid_attr_template);

                    memset(attr_template.key.prefix.algos, 0, sizeof(attr_template.key.prefix.algos));
                    attr_template.key.prefix.algo_count = 0;
                    attr_template.key.prefix.node_flag = true;
                }

                /* Default ordinal, the prefixes must not split the LSA. */
                attr_template.key.ordinal = 255;
                attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
                attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
                attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_STUB;
            }
        }

        lsdb_add_node_attr(node, &attr_template);
    }
}

void
lspgen_read_ipv6_prefix_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_ctx_ *ctx;
    struct lsdb_attr_ attr_template;
    struct lsdb_attr_ sid_attr_template;
    char *s;

    ctx = node->ctx;

    lsdb_reset_attr_template(&attr_template);
    if (json_unpack(obj, "{s:s}", "ipv6_prefix", &s) == 0) {
        scan_ipv6_prefix(s, &attr_template.key.prefix.ipv6_prefix);
        lspgen_read_common_prefix_config(&attr_template, obj);

        if (ctx->protocol_id == PROTO_ISIS) {
            attr_template.key.attr_type = ISIS_TLV_EXTD_IPV6_REACH;

        } else if (ctx->protocol_id == PROTO_OSPF3) {

            if (attr_template.key.prefix.ext_flag) {

                /* OSPF external */
                attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
                attr_template.key.attr_cp[1] = OSPF_LSA_EXTERNAL6;
                attr_template.key.start_tlv = true;

            } else {

                if (LSDB_PREFIX_HAS_SID(&attr_template.key.prefix.algos[0])) {

                    /* OSPF loopback with prefix sid, advertised in the intra-area
                     * prefix LSA and in the extended intra-area prefix LSA */
                    memcpy(&sid_attr_template, &attr_template, sizeof(sid_attr_template));
                    sid_attr_template.key.ordinal = 1;
                    sid_attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
                    sid_attr_template.key.attr_cp[1] = OSPF_LSA_E_INTRA_AREA_PREFIX;
                    sid_attr_template.key.attr_cp[2] = OSPF_TLV_INTRA_AREA_PREFIX;
                    sid_attr_template.key.attr_cp[3] = OSPF_SUBTLV_PREFIX_SID;
                    lsdb_add_node_attr(node, &sid_attr_template);

                    memset(attr_template.key.prefix.algos, 0, sizeof(attr_template.key.prefix.algos));
                    attr_template.key.prefix.algo_count = 0;
                    attr_template.key.prefix.node_flag = true;
                }

                /* Default ordinal, the prefixes must not split the LSA. */
                attr_template.key.ordinal = 255;
                attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
                attr_template.key.attr_cp[1] = OSPF_LSA_INTRA_AREA_PREFIX;
                attr_template.key.attr_cp[2] = OSPF_IA_PREFIX_LSA_PREFIX;
            }
        }

        lsdb_add_node_attr(node, &attr_template);
    }
}

void
lspgen_read_label_binding_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_attr_ attr_template;
    char *s;

    lsdb_reset_attr_template(&attr_template);
    if (json_unpack(obj, "{s:s}", "ipv4_prefix", &s) == 0) {
        scan_ipv4_prefix(s, &attr_template.key.prefix.ipv4_prefix);
        attr_template.key.prefix.family_flag = false;
        lspgen_read_common_prefix_config(&attr_template, obj);
    } else if (json_unpack(obj, "{s:s}", "ipv6_prefix", &s) == 0) {
        scan_ipv6_prefix(s, &attr_template.key.prefix.ipv6_prefix);
        attr_template.key.prefix.family_flag = true;
        lspgen_read_common_prefix_config(&attr_template, obj);
    } else {
        LOG_NOARG(ERROR, "Ignore label binding without ipv4_prefix or ipv6_prefix\n");
        return;
    }

    attr_template.key.attr_type = ISIS_TLV_BINDING;
    attr_template.key.start_tlv = true;
    lsdb_add_node_attr(node, &attr_template);
}

/*
 * Add a Flex-Algo definition, advertised in a dedicated router capability TLV.
 */
void
lspgen_add_fad_attr(lsdb_node_t *node, lsdb_attr_fad_t *fad)
{
    struct lsdb_attr_ attr_template;

    lsdb_reset_attr_template(&attr_template);
    attr_template.key.fad = *fad;
    attr_template.key.attr_type = ISIS_TLV_CAP;
    attr_template.key.attr_cp[0] = ISIS_SUBTLV_CAP_FAD;
    attr_template.key.start_tlv = true;
    attr_template.key.ordinal = 1;
    lsdb_add_node_attr(node, &attr_template);
}

/*
 * Read a Flex-Algo definition, e.g.
 * {"algo": 128, "metric_type": "min-delay", "priority": 200, "m_flag": true, "exclude_any": 1}
 */
void
lspgen_read_fad_config(lsdb_node_t *node, json_t *obj)
{
    lsdb_attr_fad_t fad;
    json_t *value;
    const char *s;

    memset(&fad, 0, sizeof(fad));
    fad.priority = LSDB_FAD_DEFAULT_PRIORITY;

    value = json_object_get(obj, "algo");
    if (!json_is_integer(value) || json_integer_value(value) < 128 || json_integer_value(value) > 255) {
        LOG_NOARG(ERROR, "Ignore Flex-Algo definition with invalid algo (128 - 255)\n");
        return;
    }
    fad.algo = json_integer_value(value);
    if (json_unpack(obj, "{s:s}", "router_id", &s) == 0) {
        scan_ipv4_address(s, (uint32_t*)fad.router_id);
    }
    if (json_unpack(obj, "{s:s}", "metric_type", &s) == 0 &&
        !lspgen_scan_fad_metric_type(s, &fad.metric_type)) {
        LOG(ERROR, "Ignore Flex-Algo definition with invalid metric_type %s\n", s);
        return;
    }
    value = json_object_get(obj, "calc_type");
    if (json_is_integer(value)) {
        fad.calc_type = json_integer_value(value);
    }
    value = json_object_get(obj, "priority");
    if (json_is_integer(value)) {
        fad.priority = json_integer_value(value);
    }
    value = json_object_get(obj, "m_flag");
    if (json_is_boolean(value)) {
        fad.m_flag = json_boolean_value(value);
    }
    value = json_object_get(obj, "exclude_any");
    if (json_is_integer(value)) {
        fad.exclude_any = json_integer_value(value);
    }
    value = json_object_get(obj, "include_any");
    if (json_is_integer(value)) {
        fad.include_any = json_integer_value(value);
    }
    value = json_object_get(obj, "include_all");
    if (json_is_integer(value)) {
        fad.include_all = json_integer_value(value);
    }
    lspgen_add_fad_attr(node, &fad);
}

void
lspgen_read_capability_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_ctx_ *ctx;
    struct lsdb_attr_ attr_template;
    json_t *value;
    json_t *arr;
    uint32_t num_arr, idx;
    char *s;

    ctx = node->ctx;

    if (json_unpack(obj, "{s:s}", "router_id", &s) == 0) {

        lsdb_reset_attr_template(&attr_template);
        scan_ipv4_address(s, (uint32_t*)attr_template.key.cap.router_id);

        value = json_object_get(obj, "s_flag");
        if (value && json_is_boolean(value)) {
            attr_template.key.cap.s_flag = json_boolean_value(value);
        }

        value = json_object_get(obj, "d_flag");
        if (value && json_is_boolean(value)) {
            attr_template.key.cap.d_flag = json_boolean_value(value);
        }

        value = json_object_get(obj, "mpls_ipv4_flag");
        if (value && json_is_boolean(value)) {
            attr_template.key.cap.mpls_ipv4_flag = json_boolean_value(value);
        }

        value = json_object_get(obj, "mpls_ipv6_flag");
        if (value && json_is_boolean(value)) {
            attr_template.key.cap.mpls_ipv6_flag = json_boolean_value(value);
        }

        value = json_object_get(obj, "srgb_base");
        if (value && json_is_integer(value)) {
            attr_template.key.cap.srgb_base = json_integer_value(value);
        }

        value = json_object_get(obj, "srgb_range");
        if (value && json_is_integer(value)) {
            attr_template.key.cap.srgb_range = json_integer_value(value);
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            attr_template.key.attr_type = ISIS_TLV_CAP;
        } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
            attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
            attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_RI;
            attr_template.key.attr_cp[2] = OSPF_TLV_SID_LABEL_RANGE;
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            arr = json_object_get(obj, "sr_algo_list");
            if (arr && json_is_array(arr)) {
                num_arr = json_array_size(arr);
                if(num_arr > sizeof(attr_template.key.cap.sr_algo)) {
                    num_arr = sizeof(attr_template.key.cap.sr_algo);
                }
                for (idx = 0; idx < num_arr; idx++) {
                    value = json_array_get(arr, idx);
                    if (!json_is_integer(value)) {
                        LOG_NOARG(ERROR, "Ignore SR algorithm which is not an integer\n");
                        continue;
                    }
                    attr_template.key.cap.sr_algo[attr_template.key.cap.sr_algo_len++] = json_integer_value(value);
                }
            }
            lspgen_read_msd_config(obj, attr_template.key.cap.msd);
        }

        attr_template.key.ordinal = 1;
        lsdb_add_node_attr(node, &attr_template);
    }
}

/*
 * Read the application-specific link attributes of an IS-IS link, e.g.
 * {"te_metric": 100, "min_delay": 1000, "max_delay": 1200, "admin_group": 1}
 */
static void
lspgen_read_link_asla_config(lsdb_attr_t *attr, json_t *link_obj)
{
    lsdb_attr_link_t *link = &attr->key.link;
    json_t *value;

    value = json_object_get(link_obj, "te_metric");
    if (json_is_integer(value)) {
        link->te_metric = json_integer_value(value) & ISIS_MAX_TE_VALUE;
        link->asla = true;
    }
    value = json_object_get(link_obj, "min_delay");
    if (json_is_integer(value)) {
        link->min_delay = json_integer_value(value) & ISIS_MAX_TE_VALUE;
        link->max_delay = link->min_delay;
        link->asla = true;
    }
    value = json_object_get(link_obj, "max_delay");
    if (json_is_integer(value)) {
        link->max_delay = json_integer_value(value) & ISIS_MAX_TE_VALUE;
        link->asla = true;
    }
    value = json_object_get(link_obj, "admin_group");
    if (json_is_integer(value)) {
        link->admin_group = json_integer_value(value);
        link->asla = true;
    }
    if (link->max_delay < link->min_delay) {
        LOG_NOARG(ERROR, "Set max_delay to min_delay\n");
        link->max_delay = link->min_delay;
    }
}

void
lspgen_read_link_config(lsdb_ctx_t *ctx, lsdb_node_t *node, json_t *link_obj, uint16_t *adj_sid)
{
    struct lsdb_link_ link_template;
    struct lsdb_attr_ attr_template;
    uint32_t metric;
    json_t *value;
    char *s;

    memset(&link_template, 0, sizeof(link_template));
    memcpy(link_template.key.local_node_id, node->key.node_id, LSDB_MAX_NODE_ID_SIZE);

    if (json_unpack(link_obj, "{s:s}", "remote_node_id", &s) == 0) {
        lsdb_scan_node_id(link_template.key.remote_node_id, s);

        value = json_object_get(link_obj, "metric");
        if (value && json_is_integer(value)) {
            link_template.link_metric = json_integer_value(value);
        }

        if (json_unpack(link_obj, "{s:s}", "local_link_id", &s) == 0) {
            lsdb_scan_node_id(link_template.key.local_link_id, s);
        }

        if (json_unpack(link_obj, "{s:s}", "remote_link_id", &s) == 0) {
            lsdb_scan_node_id(link_template.key.remote_link_id, s);
        }

        lsdb_add_link(ctx, node, &link_template);

        /* Generate an attribute for the link */
        lsdb_reset_attr_template(&attr_template);

        if (ctx->protocol_id == PROTO_ISIS) {
            value = json_object_get(link_obj, "small_metrics");
            if (value && json_is_boolean(value)) {
                attr_template.key.prefix.small_metrics = json_boolean_value(value);
            }

            /*
             * IS-IS TLV type depends on small-metrics.
             */
            if (attr_template.key.prefix.small_metrics) {
                attr_template.key.attr_type = ISIS_TLV_IS_REACH;
                attr_template.key.start_tlv = true;

                /*
                 * Clip metric.
                 */
                metric = link_template.link_metric;
                if (metric > 63) {
                    metric = 63; /* 2^6 - 1 */
                }
                attr_template.key.link.metric = metric;

            } else {
                attr_template.key.attr_type = ISIS_TLV_EXTD_IS_REACH;

                /*
                 * Clip metric.
                 */
                metric = link_template.link_metric;
                if (metric > 16777215) {
                    metric = 16777215; /* 2^24 - 1 */
                }
                attr_template.key.link.metric = metric;

                if ((uint16_t) *adj_sid > 0) {
                    attr_template.key.link.adjacency_sid = (uint16_t) *adj_sid;
                    (*adj_sid)++;
                }
                lspgen_read_link_asla_config(&attr_template, link_obj);
                lspgen_read_msd_config(link_obj, attr_template.key.link.msd);
            }

            memcpy(attr_template.key.link.remote_node_id, link_template.key.remote_node_id, 7);


        } else if (ctx->protocol_id == PROTO_OSPF2) {

            memcpy(attr_template.key.link.remote_node_id, link_template.key.remote_node_id, 4);
            memcpy(attr_template.key.link.local_link_id, link_template.key.local_link_id, 4);
            memcpy(attr_template.key.link.remote_link_id, link_template.key.remote_link_id, 4);

            attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
            attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
            attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_PTP;

            /*
             * Clip metric.
             */
            metric = link_template.link_metric;
            if (metric > 65535) {
                metric = 65535; /* 2^16 - 1 */
            }
            attr_template.key.link.metric = metric;

        } else if (ctx->protocol_id == PROTO_OSPF3) {

            memcpy(attr_template.key.link.remote_node_id, link_template.key.remote_node_id, 4);
            memcpy(attr_template.key.link.local_link_id, link_template.key.local_link_id, 4);
            memcpy(attr_template.key.link.remote_link_id, link_template.key.remote_link_id, 4);

            attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
            attr_template.key.attr_cp[1] = OSPF_LSA_ROUTER;
            attr_template.key.attr_cp[2] = OSPF_ROUTER_LSA_LINK_PTP;

            /*
             * Clip metric.
             */
            metric = link_template.link_metric;
            if (metric > 65535) {
                metric = 65535; /* 2^16 - 1 */
            }
            attr_template.key.link.metric = metric;
        }

        lsdb_add_node_attr(node, &attr_template);
    }
}

void
lspgen_read_node_config(lsdb_ctx_t *ctx, json_t *node_obj)
{
    struct lsdb_attr_ attr_template;
    struct lsdb_node_ node_template;
    struct lsdb_node_ *node;
    json_t *value;
    json_t *arr;
    uint32_t num_arr, idx;
    uint16_t adj_sid;
    char *s;

    /*
     * Read the node relevant information and create a node.
     */
    memset(&node_template, 0, sizeof(node_template));
    if (json_unpack(node_obj, "{s:s}", "node_id", &s) == 0) {
        lsdb_scan_node_id(node_template.key.node_id, s);

        if (json_unpack(node_obj, "{s:s}", "hostname", &s) == 0) {
            node_template.node_name = s;
        }

        if (json_unpack(node_obj, "{s:s}", "sequence", &s) == 0) {
            node_template.sequence = strtol(s, NULL, 0);
        }

        value = json_object_get(node_obj, "lsp_lifetime");
        if (value && json_is_integer(value)) {
            if (json_integer_value(value) >= 0 && json_integer_value(value) <= UINT16_MAX) {
                node_template.lsp_lifetime = json_integer_value(value);
            } else {
                LOG(ERROR, "Ignore lsp_lifetime %" JSON_INTEGER_FORMAT " out of range\n",
                    json_integer_value(value));
            }
        }

        node = lsdb_add_node(ctx, &node_template);
        if (!node) {
            return;
        }

        value = json_object_get(node_obj, "is_root");
        if (value && json_is_boolean(value) && json_boolean_value(value)) {
            node->is_root = true;
            memcpy(ctx->root_node_id, node->key.node_id, sizeof(ctx->root_node_id));
        }

        if (node_template.node_name) {
            lsdb_reset_attr_template(&attr_template);
            attr_template.key.ordinal = 1;

            if (ctx->protocol_id == PROTO_ISIS) {
                attr_template.key.attr_type = ISIS_TLV_HOSTNAME;
            } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
                attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
                attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_RI;
                attr_template.key.attr_cp[2] = OSPF_TLV_HOSTNAME;
            }

            strncpy(attr_template.key.hostname, node_template.node_name, sizeof(attr_template.key.hostname)-1);
            lsdb_add_node_attr(node, &attr_template);
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            value = json_object_get(node_obj, "overload");
            if (value && json_is_boolean(value)) {
                node->overload = json_boolean_value(value);
            }
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            value = json_object_get(node_obj, "attach");
            if (value && json_is_boolean(value)) {
                node->attach = json_boolean_value(value);
            }
        }

        value = json_object_get(node_obj, "adjacency_sid_base");
        if (value && json_is_integer(value)) {
            adj_sid = json_integer_value(value);
        }
        else {
            adj_sid = 0;
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            value = json_object_get(node_obj, "lsp_buffer_size");
            lsdb_reset_attr_template(&attr_template);
            attr_template.key.ordinal = 1;
            attr_template.key.attr_type = ISIS_TLV_LSP_BUFFER_SIZE;
            if (value && json_is_integer(value)) {
                node->lsp_buffer_size = json_integer_value(value);
                attr_template.key.lsp_buffer_size = node->lsp_buffer_size;
                lsdb_add_node_attr(node, &attr_template);
            }
            else {
                node->lsp_buffer_size = ISIS_DEFAULT_LSP_BUFFER_SIZE;
                attr_template.key.lsp_buffer_size = node->lsp_buffer_size;
                lsdb_add_node_attr(node, &attr_template);
            }
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            arr = json_object_get(node_obj, "area_list");
            if (arr && json_is_array(arr)) {
                num_arr = json_array_size(arr);
                for (idx = 0; idx < num_arr; idx++) {
                    lspgen_read_iso_area_config(node, json_array_get(arr, idx));
                }
            }
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            arr = json_object_get(node_obj, "protocol_list");
            if (arr && json_is_array(arr)) {
                num_arr = json_array_size(arr);
                for (idx = 0; idx < num_arr; idx++) {
                    lspgen_read_protocol_config(node, json_array_get(arr, idx));
                }
            }
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            arr = json_object_get(node_obj, "ipv4_address_list");
            if (arr && json_is_array(arr)) {
                num_arr = json_array_size(arr);
                for (idx = 0; idx < num_arr; idx++) {
                    lspgen_read_ipv4_addr_config(node, json_array_get(arr, idx));
                }
            }
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            arr = json_object_get(node_obj, "ipv6_address_list");
            if (arr && json_is_array(arr)) {
                num_arr = json_array_size(arr);
                for (idx = 0; idx < num_arr; idx++) {
                    lspgen_read_ipv6_addr_config(node, json_array_get(arr, idx));
                }
            }
        }

        arr = json_object_get(node_obj, "capability_list");
        if (arr && json_is_array(arr)) {
            num_arr = json_array_size(arr);
            for (idx = 0; idx < num_arr; idx++) {
                lspgen_read_capability_config(node, json_array_get(arr, idx));
            }
        }

        if (ctx->protocol_id == PROTO_ISIS) {
            arr = json_object_get(node_obj, "flex_algo_list");
            if (arr && json_is_array(arr)) {
                num_arr = json_array_size(arr);
                for (idx = 0; idx < num_arr; idx++) {
                    lspgen_read_fad_config(node, json_array_get(arr, idx));
                }
            }
        }

        arr = json_object_get(node_obj, "ipv4_prefix_list");
        if (arr && json_is_array(arr)) {
            num_arr = json_array_size(arr);
            for (idx = 0; idx < num_arr; idx++) {
                lspgen_read_ipv4_prefix_config(node, json_array_get(arr, idx));
            }
        }

        arr = json_object_get(node_obj, "ipv6_prefix_list");
        if (arr && json_is_array(arr)) {
            num_arr = json_array_size(arr);
            for (idx = 0; idx < num_arr; idx++) {
                lspgen_read_ipv6_prefix_config(node, json_array_get(arr, idx));
            }
        }

        arr = json_object_get(node_obj, "neighbor_list");
        if (arr && json_is_array(arr)) {
            num_arr = json_array_size(arr);
            for (idx = 0; idx < num_arr; idx++) {
                lspgen_read_link_config(ctx, node, json_array_get(arr, idx), &adj_sid);
            }
        }

        arr = json_object_get(node_obj, "label_binding_list");
        if (arr && json_is_array(arr)) {
            num_arr = json_array_size(arr);
            for (idx = 0; idx < num_arr; idx++) {
                lspgen_read_label_binding_config(node, json_array_get(arr, idx));
            }
        }
    }
}

void
lspgen_read_lsdb_config(lsdb_ctx_t *ctx, json_t *level_arr)
{
    uint32_t num_nodes, idx;

    num_nodes = json_array_size(level_arr);
    for (idx = 0; idx < num_nodes; idx++) {
        lspgen_read_node_config(ctx, json_array_get(level_arr, idx));
    }
}

void
lspgen_read_config(lsdb_ctx_t *ctx)
{
    json_t *root_obj;
    json_error_t error;
    json_t *protocol, *instance, *lsp_lifetime;
    json_t *lsdb;
    bool lsdb_found;
    const char *key;

    root_obj = json_load_file(ctx->config_filename, 0, &error);
    if (!root_obj) {
        LOG(ERROR, "Error reading config file %s, line %d: %s\n",
            ctx->config_filename, error.line, error.text);
        return;
    }

    if (json_typeof(root_obj) != JSON_OBJECT) {
        LOG(ERROR, "Error reading config file %s, root element must be object\n",
            ctx->config_filename);
        goto cleanup;
    }

    LOG(NORMAL, "Reading config file %s\n", ctx->config_filename);

    /*
     * Protocol
     */
    protocol = json_object_get(root_obj, "protocol");
    if (!protocol) {
        LOG(ERROR, "Error reading config file %s, no protocol attribute found\n",
            ctx->config_filename);
        goto cleanup;
    }
    if (!json_is_string(protocol)) {
        LOG(ERROR, "Error reading config file %s, protocol attribute is not a string\n",
            ctx->config_filename);
        goto cleanup;
    }
    ctx->protocol_id = lsdb_scan_proto(json_string_value(protocol));
    if (ctx->protocol_id == PROTO_UNKNOWN) {
        LOG(ERROR, "Error reading config file %s, unknown protocol %s\n",
            ctx->config_filename, json_string_value(protocol));
        goto cleanup;
    }

    /*
     * Instance
     */
    instance = json_object_get(root_obj, "instance");
    if (!instance) {
        LOG(ERROR, "Error reading config file %s, no instance attribute found\n",
            ctx->config_filename);
        goto cleanup;
    }
    if (!json_is_string(instance)) {
        LOG(ERROR, "Error reading config file %s, instance attribute is not a string\n",
            ctx->config_filename);
        goto cleanup;
    }
    if (ctx->instance_name) {
        free(ctx->instance_name);
    }
    ctx->instance_name = strdup(json_string_value(instance));

    /*
     * LSP lifetime. Optional.
     */
    lsp_lifetime = json_object_get(root_obj, "lsp_lifetime");
    if (lsp_lifetime) {
        if (!json_is_integer(lsp_lifetime)) {
            LOG(ERROR, "Error reading config file %s, lsp_lifetime attribute is not an integer\n",
                ctx->config_filename);
            goto cleanup;
        }
        if (json_integer_value(lsp_lifetime) < 0 || json_integer_value(lsp_lifetime) > UINT16_MAX) {
            LOG(ERROR, "Error reading config file %s, lsp_lifetime attribute out of range\n",
                ctx->config_filename);
            goto cleanup;
        }
        ctx->lsp_lifetime = json_integer_value(lsp_lifetime);
        if (ctx->lsp_lifetime < LSP_LIFETIME_MIN) {
            ctx->lsp_lifetime = LSP_LIFETIME_MIN;
            LOG(ERROR, "Set lsp-lifetime to min %us\n", ctx->lsp_lifetime);
        }
    }

    /* Iterate through all top level objects */
    lsdb_found = false;
    json_object_foreach(root_obj, key, lsdb) {

        /*
         * Hunt for the level<N>, area<N> lsdb.
         */
        if (!json_is_array(lsdb)) {
            continue;
        }

        /* OSPF */
        if (strncmp(key, "area", 4) == 0) {
            if (inet_pton(AF_INET, &key[4], &ctx->topology_id.area) != 1) {
                LOG(ERROR, "Error reading config file %s, invalid area %s\n", ctx->config_filename, key);
                goto cleanup;
            }
            lspgen_read_lsdb_config(ctx, lsdb);
            lsdb_found = true;
            break;
        }

        /* IS-IS */
        if (strncmp(key, "level", 5) == 0) {
            ctx->topology_id.level = strtol(&key[5], NULL, 10);
            lspgen_read_lsdb_config(ctx, lsdb);
            lsdb_found = true;
            break;
        }
    }

    if (!lsdb_found) {
        LOG(ERROR, "Error reading config file %s, no level1|2 or area<n.n.n.n> array found\n",
            ctx->config_filename);
    }

cleanup:
    json_decref(root_obj);
}
