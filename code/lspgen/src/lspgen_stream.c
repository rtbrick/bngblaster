/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * BNG Blaster Stream file generation
 *
 * Hannes Gredler, February 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */

#include <jansson.h>
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"

void
lspgen_dump_ipv4_stream(json_t *dest_arr, ipv4_prefix *prefix)
{
    json_t *obj, *str;

    obj = json_object();
    str = json_string(format_ipv4_address(&prefix->address));
    json_object_set_new(obj, "destination-ipv4-address", str);
    json_array_append_new(dest_arr, obj);
}

void
lspgen_dump_ipv6_stream(json_t *dest_arr, ipv6_prefix *prefix)
{
    json_t *obj, *str;

    obj = json_object();
    str = json_string(format_ipv6_address(&prefix->address));
    json_object_set_new(obj, "destination-ipv6-address", str);
    json_array_append_new(dest_arr, obj);
}

void
lspgen_gen_stream_node(__attribute__((unused))lsdb_ctx_t *ctx,
                       lsdb_node_t *node, json_t *dest_arr)
{
    struct lsdb_attr_ *attr;
    dict_itor *itor;

    /*
     * Walk the node attributes.
     */
    itor = dict_itor_new(node->attr_dict);
    if (!itor) {
        return;
    }

    /*
     * Node DB empty?
     */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }

    do {
        attr = *dict_itor_datum(itor);
        switch (attr->key.attr_type) {
            case ISIS_TLV_EXTD_IPV4_REACH:
                lspgen_dump_ipv4_stream(dest_arr, &attr->key.prefix.ipv4_prefix);
                break;
            case ISIS_TLV_EXTD_IPV6_REACH:
                lspgen_dump_ipv6_stream(dest_arr, &attr->key.prefix.ipv6_prefix);
                break;
            default:
                break;
        }
    } while (dict_itor_next(itor));

    dict_itor_free(itor);
}


void
lspgen_dump_stream(lsdb_ctx_t *ctx)
{
    struct lsdb_node_ *node;
    dict_itor *itor;
    json_t *root_obj, *dest_arr;
    int res;

    ctx->stream_file = fopen(ctx->stream_filename, "w");
    if (!ctx->stream_file) {
        LOG(ERROR, "Error opening stream file %s\n", ctx->stream_filename);
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
     * Node DB empty?
     */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG_NOARG(ERROR, "Empty LSDB.\n");
        return;
    }

    root_obj = json_object();
    dest_arr = json_array();
    json_object_set_new(root_obj, "destinations", dest_arr);

    do {
        node = *dict_itor_datum(itor);
        lspgen_gen_stream_node(ctx, node, dest_arr);
    } while (dict_itor_next(itor));
    dict_itor_free(itor);

    res = json_dumpf(root_obj, ctx->stream_file, JSON_INDENT(2));
    if (res == -1) {
        LOG(ERROR, "Error generating stream file %s\n", ctx->stream_filename);
    }

    /* done */
    json_decref(root_obj);
    fclose(ctx->stream_file);
    ctx->stream_file = NULL;
}