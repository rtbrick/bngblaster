/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * PCAP file support.
 *
 * Hannes Gredler, February 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"

#define PCAPNG_SHB 0x0a0d0d0a
#define PCAPNG_SHB_USERAPPL_OPTION 4
#define PCAPNG_SHB_USERAPPL "rtbrick-lspgen"

#define PCAPNG_IDB 0x00000001
#define PCAPNG_IDB_IFNAME_OPTION 2

#define PCAPNG_EPB 0x00000006

#define DLT_EN10MB 1 /* Ethernet (10Mb) */

/*
 * Calculate padding bytes.
 */
static uint32_t
calc_pad(uint32_t length)
{
    switch (length % 4) {
        case 3:
            return 1;
        case 2:
            return 2;
        case 1:
            return 3;
        case 0:
            return 0;
    }
    return 0;
}

void
pcapng_push_section_header(struct io_buffer_ *buf)
{
    uint32_t start_idx, total_length, option_length;

    start_idx = buf->idx;

    push_le_uint(buf, 4, PCAPNG_SHB); /* block type */
    push_le_uint(buf, 4, 0); /* block total_length */
    push_le_uint(buf, 4, 0x1a2b3c4d); /* byte order magic */
    push_le_uint(buf, 2, 1); /* version_major */
    push_le_uint(buf, 2, 0); /* version_minor */
    push_le_uint(buf, 8, 0xffffffffffffffff); /* section length */

    /*
     * Write shb_userappl option
     */
    push_le_uint(buf, 2, PCAPNG_SHB_USERAPPL_OPTION); /* option_type */
    option_length = snprintf((char *)buf->data + buf->idx + 2,
                 buf->size - buf->idx - 2,
                 "%s", PCAPNG_SHB_USERAPPL);
    push_le_uint(buf, 2, option_length); /* option_length */
    buf->idx += option_length;
    push_le_uint(buf, calc_pad(option_length), 0);

    /*
     * Calculate total length field. It occurs twice. Overwrite and append.
     */
    total_length = buf->idx - start_idx + 4;
    write_le_uint(buf->data+start_idx+4, 4, total_length); /* block total_length */
    push_le_uint(buf, 4, total_length); /* block total_length */
}

/*
 * Write a pcapng interface header block.
 */
void
pcapng_push_interface_header (struct io_buffer_ *buf, uint32_t dlt, const char *if_name)
{
    uint32_t start_idx, total_length, option_length;

    start_idx = buf->idx;

    push_le_uint(buf, 4, PCAPNG_IDB); /* block type */
    push_le_uint(buf, 4, 0); /* block total_length */
    push_le_uint(buf, 2, dlt); /* link_type */
    push_le_uint(buf, 2, 0); /* reserved */
    push_le_uint(buf, 4, 9*1024); /* snaplen */

    /*
     * Write idb_ifname option
     */
    push_le_uint(buf, 2, PCAPNG_IDB_IFNAME_OPTION); /* option_type */
    option_length = snprintf((char *)buf->data+buf->idx+2, buf->size-buf->idx-2, "%s", if_name);
    push_le_uint(buf, 2, option_length); /* option_length */
    buf->idx += option_length;
    push_le_uint(buf, calc_pad(option_length), 0);

    /*
     * Calculate total length field. It occurs twice. Overwrite and append.
     */
    total_length = buf->idx - start_idx + 4;
    write_le_uint(buf->data+start_idx+4, 4, total_length); /* block total_length */
    push_le_uint(buf, 4, total_length); /* block total_length */
}

/*
 * Write all the generated LSPs of a single node into a pcap file.
 */
void
lspgen_dump_pcap_node (struct lsdb_ctx_ *ctx, struct lsdb_node_ *node)
{
    struct lsdb_packet_ *packet;
    dict_itor *itor;
    struct io_buffer_ buf;
    uint8_t pcap_packet[sizeof(packet->data)+64]; /* pcap header overhead */
    uint32_t total_length, eth_header_length;
    struct timespec now;
    uint64_t ts_usec;

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
        buf.data = pcap_packet;
        buf.size = sizeof(pcap_packet);
        buf.idx = 0;

        push_le_uint(&buf, 4, PCAPNG_EPB); /* block type */
        push_le_uint(&buf, 4, 0); /* block total_length */
        push_le_uint(&buf, 4, 0); /* interface_id */

        clock_gettime(CLOCK_REALTIME, &now);
        ts_usec = now.tv_sec * 1000000 + now.tv_nsec/1000;
        push_le_uint(&buf, 4, ts_usec>>32); /* timestamp usec msb */
        push_le_uint(&buf, 4, ts_usec & 0xffffffff); /* timestamp usec lsb */

	eth_header_length = 0;

	if (ctx->protocol_id == PROTO_ISIS) {

	    /* IS-IS */

	    /* Account for the the faked ethernet & LLC header */
	    eth_header_length = 17;
	    push_le_uint(&buf, 4, packet->buf.idx+eth_header_length); /* captured packet length */
	    push_le_uint(&buf, 4, packet->buf.idx+eth_header_length); /* original packet length */

	    /* Fake an Ethernet & LLC header */
	    push_be_uint(&buf, 6, 0x0180c2000014); /* Destination MAC */
	    push_be_uint(&buf, 6, 0xf41e5e000000); /* Source MAC MAC */
	    push_be_uint(&buf, 2, packet->buf.idx+3); /* Length + DSAP, SSAP, Mode */
	    push_be_uint(&buf, 3, 0xfefe03); /* OSI DSAP, SSAP, Mode */

	} else if (ctx->protocol_id == PROTO_OSPF2) {

	    /* OSPFv2 */

	    /* Account for the faked Ethernet header */
	    eth_header_length = 14;
	    push_le_uint(&buf, 4, packet->buf.idx+eth_header_length); /* captured packet length */
	    push_le_uint(&buf, 4, packet->buf.idx+eth_header_length); /* original packet length */

	    /* Fake an Ethernet header */
	    push_be_uint(&buf, 6, 0x01005e000005); /* Destination MAC */
	    push_be_uint(&buf, 6, 0xf41e5e000000); /* Source MAC MAC */
	    push_be_uint(&buf, 2, 0x0800); /* Ethertype */

	} else if (ctx->protocol_id == PROTO_OSPF3) {

	    /* OSPFv3 */

	    /* Account for the faked Ethernet header */
	    eth_header_length = 14;
	    push_le_uint(&buf, 4, packet->buf.idx+eth_header_length); /* captured packet length */
	    push_le_uint(&buf, 4, packet->buf.idx+eth_header_length); /* original packet length */

	    /* Fake an Ethernet header */
	    push_be_uint(&buf, 6, 0x333300000005); /* Destination MAC */
	    push_be_uint(&buf, 6, 0xf41e5e000000); /* Source MAC MAC */
	    push_be_uint(&buf, 2, 0x86dd); /* Ethertype */
	}

        /*
         * Copy packet
         */
        memcpy(&pcap_packet[buf.idx], packet->data, packet->buf.idx);
        buf.idx += packet->buf.idx;
        push_le_uint(&buf, calc_pad(packet->buf.idx+eth_header_length), 0); /* write pad bytes */

        /*
         * Calculate total length field. It occurs twice. Overwrite and append.
         */
        total_length = buf.idx + 4;
        write_le_uint(buf.data+4, 4, total_length); /* block total_length */
        push_le_uint(&buf, 4, total_length); /* block total_length */

        fwrite(buf.data, buf.idx, 1, ctx->pcap_file);

        LOG(DEBUG, "wrote %u bytes pcap packet data\n", buf.idx);

    } while (dict_itor_next(itor));
    dict_itor_free(itor);
}

/*
 * Walk the LSDB and write all the generated LSPs into a PCAP file.
 */
void
lspgen_dump_pcap (struct lsdb_ctx_ *ctx)
{
    struct lsdb_node_ *node;
    dict_itor *itor;
    uint8_t pcap_header[256];
    struct io_buffer_ buf;

    ctx->pcap_file = fopen(ctx->pcap_filename, "w");
    if (!ctx->pcap_file) {
        LOG(ERROR, "Error opening PCAP file %s\n", ctx->pcap_filename);
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

    /*
     * Write the section & interface header.
     */
    buf.data = pcap_header;
    buf.idx = 0;
    buf.size = sizeof(pcap_header);
    pcapng_push_section_header(&buf);
    pcapng_push_interface_header(&buf, DLT_EN10MB, "lspgen");
    fwrite(buf.data, buf.idx, 1, ctx->pcap_file);

    do {
        node = *dict_itor_datum(itor);
        lspgen_dump_pcap_node(ctx, node);
    } while (dict_itor_next(itor));
    dict_itor_free(itor);

    /* done */
    fclose(ctx->pcap_file);
    ctx->pcap_file = NULL;
}
