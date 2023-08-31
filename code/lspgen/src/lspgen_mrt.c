/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * MRT file support.
 *
 * Hannes Gredler, February 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */

#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"

/* https://datatracker.ietf.org/doc/html/rfc6396#section-4 */
#define MRT_TYPE_OSPFV2 11
#define MRT_TYPE_ISIS   32

/*
 * Write all the generated LSPs of a single node into a MRT file.
 */
void
lspgen_dump_mrt_node(lsdb_ctx_t *ctx, lsdb_node_t *node)
{
    struct lsdb_packet_ *packet;
    dict_itor *itor;
    struct io_buffer_ buf;
    uint8_t mrt_record[sizeof(packet->data)+12];
    uint32_t length;

    itor = dict_itor_new(node->packet_dict);
    if (!itor) {
        return;
    }

    /*
     * Packet dict empty ?
     */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        return;
    }

    do {
        packet = *dict_itor_datum(itor);

        /*
         * Init write buffer.
         */
        buf.data = mrt_record;
        buf.size = sizeof(mrt_record);
        buf.idx = 0;

        push_be_uint(&buf, 4, ctx->now); /* timestamp */

	switch(ctx->protocol_id) {
	case PROTO_ISIS:
	    push_be_uint(&buf, 2, MRT_TYPE_ISIS); /* type */
	    push_be_uint(&buf, 2, 0); /* subtype */
	    push_be_uint(&buf, 4, 0); /* length, will be overwritten */

	    /*
	     * Copy packet
	     */
	    memcpy(&mrt_record[buf.idx], packet->data, packet->buf.idx);
	    buf.idx += packet->buf.idx;
	    break;

	case PROTO_OSPF2:
	    push_be_uint(&buf, 2, MRT_TYPE_OSPFV2); /* type */
	    push_be_uint(&buf, 2, 0); /* subtype */
	    push_be_uint(&buf, 4, 0); /* length, will be overwritten */

	    push_be_uint(&buf, 4, 0); /* remote IP address */
	    push_be_uint(&buf, 4, 0); /*  local IP address */

	    /*
	     * Copy packet
	     */
	    if (packet->buf.idx > 20) {

		/*
		 * Skip 20 bytes of IPv4 header.
		 */
		memcpy(&mrt_record[buf.idx], packet->data+20, packet->buf.idx-20);
		buf.idx += packet->buf.idx-20;
	    }
	    break;

	default:
	    LOG(ERROR, "No MRT writer for protocol %u\n", ctx->protocol_id);
	    return;
	}

        length = buf.idx-12;
        write_be_uint(buf.data+8, 4, length); /* overwrite length field */

        fwrite(buf.data, buf.idx, 1, ctx->mrt_file);

        LOG(DEBUG, "wrote %u bytes mrt packet data\n", buf.idx);
    } while (dict_itor_next(itor));
    dict_itor_free(itor);
}

/*
 * Walk the LSDB and write all the generated LSPs into a MRT file.
 */
void
lspgen_dump_mrt(lsdb_ctx_t *ctx)
{
    struct lsdb_node_ *node;
    dict_itor *itor;

    ctx->mrt_file = fopen(ctx->mrt_filename, "w");
    if (!ctx->mrt_file) {
        LOG(ERROR, "Error opening MRT file %s\n", ctx->mrt_filename);
        return;
    }

    /*
     * Walk the node DB.
     */
    itor = dict_itor_new(ctx->node_dict);
    if (!itor) {
        return;
    }

    time(&ctx->now);

    /*
     * Node DB empty ?
     */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG_NOARG(ERROR, "Empty LSDB.\n");
        return;
    }

    do {
        node = *dict_itor_datum(itor);
        lspgen_dump_mrt_node(ctx, node);
    } while (dict_itor_next(itor));
    dict_itor_free(itor);

    /* done */
    fclose(ctx->mrt_file);
    ctx->mrt_file = NULL;
}
