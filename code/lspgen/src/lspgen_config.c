/*
 * LSPGEN - Configuration
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"
#include "lspgen_ospf.h"

void
lspgen_write_area_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *str;

    str = json_string(format_iso_prefix(&attr->key.area));
    json_array_append(arr, str);
    json_decref(str);
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
    json_array_append(arr, obj);
    json_decref(obj);
}

void
lspgen_write_cap_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str;

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
    json_array_append(arr, obj);
    json_decref(obj);
}

/*
 * Common function shared between ipv4_prefix,
 * ipv6_prefix and label_binding writers.
 */
void
lspgen_write_common_prefix_config(json_t *obj, lsdb_attr_t *attr)
{
    json_object_set_new(obj, "metric", json_integer(attr->key.prefix.metric));
    if (attr->key.prefix.adv_sid) {
        json_object_set_new(obj, "segment_id", json_integer(attr->key.prefix.sid));
    }
    if (attr->key.prefix.adv_tag) {
        json_object_set_new(obj, "tag", json_integer(attr->key.prefix.tag));
    }
    if (attr->key.prefix.adv_range) {
        json_object_set_new(obj, "range", json_integer(attr->key.prefix.tag));
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
}

void
lspgen_write_ipv4_addr_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *str;

    str = json_string(format_ipv4_address((uint32_t*)attr->key.ipv4_addr));
    json_array_append(arr, str);
    json_decref(str);
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
    json_array_append(arr, str);
    json_decref(str);
}

void
lspgen_write_ipv4_prefix_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str;

    obj = json_object();
    str = json_string(format_ipv4_prefix(&attr->key.prefix.ipv4_prefix));
    json_object_set_new(obj, "ipv4_prefix", str);
    lspgen_write_common_prefix_config(obj, attr);
    json_array_append(arr, obj);
    json_decref(obj);
}

void
lspgen_write_ipv6_addr_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *str;

    str = json_string(format_ipv6_address((ipv6addr_t*)attr->key.ipv6_addr));
    json_array_append(arr, str);
    json_decref(str);
}

void
lspgen_write_ipv6_prefix_config(json_t *arr, lsdb_attr_t *attr)
{
    json_t *obj, *str;

    obj = json_object();
    str = json_string(format_ipv6_prefix(&attr->key.prefix.ipv6_prefix));
    json_object_set_new(obj, "ipv6_prefix", str);
    lspgen_write_common_prefix_config(obj, attr);
    json_array_append(arr, obj);
    json_decref(obj);
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
    json_array_append(arr, obj);
    json_decref(obj);
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

    node_obj = json_object();
    lspgen_write_node_common_config(ctx, node, node_obj);

    /* Walk the node attributes. */
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

    json_array_append(level_arr, node_obj);
    json_decref(node_obj);

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

    node_obj = json_object();
    lspgen_write_node_common_config(ctx, node, node_obj);

    /* Walk the node attributes. */
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

    json_array_append(level_arr, node_obj);
    json_decref(node_obj);

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
    json_t *binding_arr = NULL;

    node_obj = json_object();
    lspgen_write_node_common_config(ctx, node, node_obj);

    /* Walk the node attributes. */
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

    json_array_append(level_arr, node_obj);
    json_decref(node_obj);

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
    char ospf_area[sizeof("255.255.255.255")];

    ctx->config_file = fopen(ctx->config_filename, "w");
    if (!ctx->config_file) {
        LOG(ERROR, "Error opening config file %s\n", ctx->config_filename);
        return;
    }

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

    root_obj = json_object();
    json_object_set_new(root_obj, "instance", json_string(ctx->instance_name));
    json_object_set_new(root_obj, "protocol", json_string(lsdb_format_proto(ctx)));
    arr = json_array();

    switch (ctx->protocol_id) {
    case PROTO_ISIS:
	json_object_set_new(root_obj, val2key(isis_level_names, ctx->topology_id.level), arr);
	break;
    case PROTO_OSPF2: /* fall through */
    case PROTO_OSPF3:
	snprintf(ospf_area, sizeof(ospf_area)-1, "area%s", format_ipv4_address(&ctx->topology_id.area));
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
void
lspgen_read_common_prefix_config(lsdb_attr_t *attr, json_t *obj)
{
    json_t *value;

    value = json_object_get(obj, "metric");
    if (value && json_is_integer(value)) {
        attr->key.prefix.metric = json_integer_value(value);
    }
    value = json_object_get(obj, "segment_id");
    if (value && json_is_integer(value)) {
        attr->key.prefix.sid = json_integer_value(value);
        attr->key.prefix.adv_sid = true;
    }
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
}

void
lspgen_read_ipv4_prefix_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_ctx_ *ctx;
    struct lsdb_attr_ attr_template;
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

	    if (attr_template.key.prefix.node_flag &&
		attr_template.key.prefix.adv_sid) {

		/* OSPF loopback with prefix sid*/
		attr_template.key.ordinal = 1;
		attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
		attr_template.key.attr_cp[1] = OSPF_LSA_OPAQUE_AREA_EP;
		attr_template.key.attr_cp[2] = OSPF_TLV_EXTENDED_PREFIX;
		attr_template.key.attr_cp[3] = OSPF_SUBTLV_PREFIX_SID;

	    } else if (attr_template.key.prefix.ext_flag) {

		/* OSPF external */
		attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
		attr_template.key.attr_cp[1] = OSPF_LSA_EXTERNAL;
		attr_template.key.start_tlv = true;
	    } else {

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
    char *s;

    ctx = node->ctx;

    lsdb_reset_attr_template(&attr_template);
    if (json_unpack(obj, "{s:s}", "ipv6_prefix", &s) == 0) {
        scan_ipv6_prefix(s, &attr_template.key.prefix.ipv6_prefix);
        lspgen_read_common_prefix_config(&attr_template, obj);

	if (ctx->protocol_id == PROTO_ISIS) {
	    attr_template.key.attr_type = ISIS_TLV_EXTD_IPV6_REACH;

	} else if (ctx->protocol_id == PROTO_OSPF3) {

	    if (attr_template.key.prefix.node_flag &&
		attr_template.key.prefix.adv_sid) {

		/* OSPF loopback with prefix sid*/
		attr_template.key.ordinal = 1;
		attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
		attr_template.key.attr_cp[1] = OSPF_LSA_E_INTRA_AREA_PREFIX;
		attr_template.key.attr_cp[2] = OSPF_TLV_INTRA_AREA_PREFIX;
		attr_template.key.attr_cp[3] = OSPF_SUBTLV_PREFIX_SID;

	    } else if (attr_template.key.prefix.ext_flag) {

		/* OSPF external */
		attr_template.key.attr_cp[0] = OSPF_MSG_LSUPDATE;
		attr_template.key.attr_cp[1] = OSPF_LSA_EXTERNAL6;
		attr_template.key.start_tlv = true;

	    } else {

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
    }
    if (json_unpack(obj, "{s:s}", "ipv6_prefix", &s) == 0) {
        scan_ipv6_prefix(s, &attr_template.key.prefix.ipv6_prefix);
        attr_template.key.prefix.family_flag = true;
        lspgen_read_common_prefix_config(&attr_template, obj);
    }

    attr_template.key.attr_type = ISIS_TLV_BINDING;
    attr_template.key.start_tlv = true;
    lsdb_add_node_attr(node, &attr_template);
}

void
lspgen_read_capability_config(lsdb_node_t *node, json_t *obj)
{
    struct lsdb_ctx_ *ctx;
    struct lsdb_attr_ attr_template;
    json_t *value;
    char *s;

    ctx = node->ctx;

    if (json_unpack(obj, "{s:s}", "router_id", &s) == 0) {

    lsdb_reset_attr_template(&attr_template);
    scan_ipv4_address(s, (uint32_t*)attr_template.key.cap.router_id);

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

    attr_template.key.ordinal = 1;
    lsdb_add_node_attr(node, &attr_template);
    }
}

void
lspgen_read_link_config(lsdb_ctx_t *ctx, lsdb_node_t *node, json_t *link_obj)
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
	    }

	    memcpy(attr_template.key.link.remote_node_id, link_template.key.remote_node_id, 7);


	} else if (ctx->protocol_id == PROTO_OSPF2) {

	    memcpy(attr_template.key.link.remote_node_id, link_template.key.remote_node_id, 4);

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
        node = lsdb_add_node(ctx, &node_template);

        if (node_template.node_name) {
            lsdb_reset_attr_template(&attr_template);
            attr_template.key.ordinal = 1;

	    if (ctx->protocol_id == PROTO_ISIS) {
		attr_template.key.attr_type = ISIS_TLV_HOSTNAME;
	    } else if (ctx->protocol_id == PROTO_OSPF2) {
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

        if (json_unpack(node_obj, "{s:s}", "sequence", &s) == 0) {
            node->sequence = strtol(s, NULL, 0);
        }

        value = json_object_get(node_obj, "lsp_lifetime");
        if (value && json_is_integer(value)) {
            node->lsp_lifetime = json_integer_value(value);
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
                lspgen_read_link_config(ctx, node, json_array_get(arr, idx));
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
    json_t *protocol, *instance;
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
        return;
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
	if (strstr(key, "area")) {
	    inet_pton(AF_INET, &key[4], &ctx->topology_id.area);
	    lspgen_read_lsdb_config(ctx, lsdb);
	    lsdb_found = true;
	    break;
	}

	/* IS-IS */
	if (strstr(key, "level")) {
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
