/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * BNG Blaster Control socket support.
 *
 * Hannes Gredler, February 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"

/*
 * Write all the generated LSPs of a single node to the packet_change list.
 */
static void
lspgen_enqueue_node_packets(lsdb_ctx_t *ctx, lsdb_node_t *node)
{
    struct lsdb_packet_ *packet;
    dict_itor *itor;

    itor = dict_itor_new(node->packet_dict);
    if (!itor) {
        return;
    }

    /*
     * Packet dict empty?
     */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        return;
    }

    do {
        packet = *dict_itor_datum(itor);

        if (packet->on_change_list) {
            CIRCLEQ_REMOVE(&ctx->packet_change_qhead, packet, packet_change_qnode);
	    ctx->ctrl_stats.packets_queued--;
        }
        CIRCLEQ_INSERT_TAIL(&ctx->packet_change_qhead, packet, packet_change_qnode);
        packet->on_change_list = true;
        ctx->ctrl_stats.packets_queued++;
    } while (dict_itor_next(itor));
    dict_itor_free(itor);
}

/*
 * Walk the LSDB and enqueue all the generated LSPs to the packet_change list.
 */
void
lspgen_enqueue_all_packets(lsdb_ctx_t *ctx)
{
    struct lsdb_node_ *node;
    dict_itor *itor;

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

    do {
        node = *dict_itor_datum(itor);
        lspgen_enqueue_node_packets(ctx, node);
    } while (dict_itor_next(itor));
    dict_itor_free(itor);
}

static void
lspgen_write_ctrl_buffer(lsdb_ctx_t *ctx)
{
    uint8_t *buffer_start;
    int buffer_len, res;

    buffer_start = ctx->ctrl_io_buf.data + ctx->ctrl_io_buf.start_idx;
    buffer_len =  ctx->ctrl_io_buf.idx - ctx->ctrl_io_buf.start_idx;

    if (!buffer_len) {
        /* nothing in buffer */
        return;
    }

    res = write(ctx->ctrl_socket_sockfd, buffer_start, buffer_len);

    /*
     * Blocked ?
     */
    if (res == -1) {
        switch (errno) {
            case EAGAIN:
                return;
            case EPIPE:
                /*
                 * Remote has closed the connection. Restart.
                 */
                timer_del(ctx->ctrl_socket_write_timer);
                timer_add_periodic(&ctx->timer_root, &ctx->ctrl_socket_connect_timer,
                                   "connect", 1, 0, ctx, &lspgen_ctrl_connect_cb);

		/*
		 * Requeue all packets to the change list.
		 */
		lspgen_enqueue_all_packets(ctx);
		LOG(ERROR, "Requeued %u packets to %s\n", ctx->ctrl_stats.packets_queued, ctx->ctrl_socket_path);

		return;
            default:
                LOG(ERROR, "write(): error %s (%d)\n", strerror(errno), errno);
                break;
        }
        return;
    }

    /*
     * Full write ?
     */
    if (res == buffer_len) {
        LOG(CTRL, "Full write %u bytes buffer to %s\n", res, ctx->ctrl_socket_path);
        /*
         * Reset the buffer.
         */
        ctx->ctrl_io_buf.start_idx = 0;
        ctx->ctrl_io_buf.idx = 0;
        ctx->ctrl_stats.octets_sent += res;
        return;
    }

    /*
     * Partial write ?
     */
    if (res && res < buffer_len) {
        LOG(CTRL, "Partial write %u bytes buffer to %s\n", res, ctx->ctrl_socket_path);
        ctx->ctrl_stats.octets_sent += res;
        /*
         * Rebase the buffer.
         */
        memmove(ctx->ctrl_io_buf.data, buffer_start+res, ctx->ctrl_io_buf.idx - res);
        ctx->ctrl_io_buf.start_idx = 0;
        ctx->ctrl_io_buf.idx -= res;
        return;
    }
}

/*
 * Encode a packet as a hexdump.
 */
static void
lspgen_ctrl_encode_packet(lsdb_ctx_t *ctx, lsdb_packet_t *packet)
{
    struct io_buffer_ *buf, *src_buf;
    char hextable[] = "0123456789abcdef";
    uint8_t hi_byte, lo_byte;
    uint32_t idx, val;

    buf = &ctx->ctrl_io_buf;

    if (ctx->ctrl_packet_first) {
        ctx->ctrl_packet_first = false; /* omit comma for first packet */
    } else {
        push_be_uint(buf, 1, ',');
        push_be_uint(buf, 1, '\n');
    }
    push_be_uint(buf, 1, '"');

    idx = 0;
    if (ctx->protocol_id == PROTO_OSPF2) {
        /* Omit the IPv4 header (the first 20 bytes). */
        idx = 20;
    } else if (ctx->protocol_id == PROTO_OSPF3) {
        /* Omit the IPv6 header (the first 40 bytes). */
        idx = 40;
    }

    src_buf = &packet->buf[0];
    for (; idx < src_buf->idx; idx++) {
        hi_byte = src_buf->data[idx] >> 4;
        lo_byte = src_buf->data[idx] & 0xf;

        val = (hextable[hi_byte] << 8) | hextable[lo_byte];
        push_be_uint(buf, 2, val);
    }
    push_be_uint(buf, 1, '"');

    ctx->ctrl_stats.packets_sent++;
}

void
lspgen_ctrl_close_cb(timer_s *timer)
{
    struct lsdb_ctx_ *ctx;

    ctx = timer->data;

    /*
     * Kill the write timer.
     */
     timer_del(ctx->ctrl_socket_write_timer);

     /*
      * Close the connection.
      */
     if (ctx->ctrl_socket_sockfd > 0) {
	 close(ctx->ctrl_socket_sockfd);
	 ctx->ctrl_socket_sockfd = 0;
     }
     LOG(NORMAL, "Closing connection to %s\n", ctx->ctrl_socket_path);

     /*
      * Terminate the event loop if user wants.
      */
     if (ctx->quit_loop) {
	 lspgen_quit_loop();
     }
}

bool
lspgen_buffer_is_empty (lsdb_ctx_t *ctx) {
    if (ctx->ctrl_io_buf.idx - ctx->ctrl_io_buf.start_idx) {
	return false;
    } else {
	return true;
    }
}

void
lspgen_ctrl_write_cb(timer_s *timer)
{
    char *json_header, *json_footer;
    struct lsdb_ctx_ *ctx;
    struct lsdb_packet_ *packet;
    uint32_t buffer_left;

    ctx = timer->data;

    /*
     * First flush the ctrl socket buffer.
     */
    lspgen_write_ctrl_buffer(ctx);

    if (CIRCLEQ_EMPTY(&ctx->packet_change_qhead)) {
        /* nothing to do */
        return;
    }

    if (ctx->ctrl_packet_first) {
        /*
	 * Write JSON header.
	 */
	json_header = NULL;
	if (ctx->protocol_id == PROTO_ISIS) {
	    json_header = "{\n\"command\": \"isis-lsp-update\",\n"
		"\"arguments\": {\n\"instance\": 1,\n\"pdu\": [";
	} else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	    json_header = "{\n\"command\": \"ospf-pdu-update\",\n"
		"\"arguments\": {\n\"instance\": 1,\n\"pdu\": [";
	}
	if (!json_header) {
        LOG_NOARG(ERROR, "Unknown protocol\n");
        return;
	}
        push_data(&ctx->ctrl_io_buf, (uint8_t *)json_header, strlen(json_header));
    }

    /*
     * Drain the change queue as long as there is buffer left.
     */
     while (!CIRCLEQ_EMPTY(&ctx->packet_change_qhead)) {
        packet = CIRCLEQ_FIRST(&ctx->packet_change_qhead);

        buffer_left = ctx->ctrl_io_buf.size - ctx->ctrl_io_buf.idx;

        /*
	 * Hexdumping doubles the data plus 4 bytes for two quotation marks, comma and whitespace.
	 */
        if (buffer_left < ((packet->buf[0].idx * 2) + 4)) {

            /* no space, release buffer and try later */
            lspgen_write_ctrl_buffer(ctx);
            LOG(NORMAL, "Sent %u packets, %u bytes to %s\n",
            ctx->ctrl_stats.packets_sent,
            ctx->ctrl_stats.octets_sent,
            ctx->ctrl_socket_path);
            return;
        }

        lspgen_ctrl_encode_packet(ctx, packet);

        /*
	 * Packet got encoded, take packet off the change queue.
	 */
        CIRCLEQ_REMOVE(&ctx->packet_change_qhead, packet, packet_change_qnode);
        packet->on_change_list = false;
        ctx->ctrl_stats.packets_queued--;
    }

     json_footer = "]\n}\n}\n";
     push_data(&ctx->ctrl_io_buf, (uint8_t *)json_footer, strlen(json_footer));
     lspgen_write_ctrl_buffer(ctx);

     /*
      * Optimization.
      * If the buffer has been fully drained then kill the write timer right away,
      * else keep it running. It will be killed once the close timer fires.
      */
     if (lspgen_buffer_is_empty(ctx)) {
	 timer_del(ctx->ctrl_socket_write_timer);
     }

     LOG(NORMAL, "Sent %u packets, %u bytes to %s\n",
     ctx->ctrl_stats.packets_sent,
     ctx->ctrl_stats.octets_sent,
     ctx->ctrl_socket_path);

     /*
      * For once, close the connection.
      */
     timer_add(&ctx->timer_root, &ctx->ctrl_socket_close_timer, "close",
               1, 0, ctx, &lspgen_ctrl_close_cb);
}

/*
 * Dummy timer for not sleeping too long in the event loop.
 */
void
lspgen_ctrl_wakeup_cb(__attribute__((unused))timer_s *timer)
{
}

void
lspgen_ctrl_connect_cb(timer_s *timer)
{
    struct sockaddr_un addr;
    struct lsdb_ctx_ *ctx;
    int res;

    ctx = timer->data;

    if (ctx->ctrl_socket_close_timer) {
	LOG(CTRL, "Close timer to %s still running, retry later\n", ctx->ctrl_socket_path);
	return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ctx->ctrl_socket_path, sizeof(addr.sun_path)-1);
    if (ctx->ctrl_socket_sockfd != 0) {
	LOG(CTRL, "CTRL socket to %s still unfreed\n", ctx->ctrl_socket_path);
    }
    ctx->ctrl_socket_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    res = connect(ctx->ctrl_socket_sockfd, (struct sockaddr *)&addr, SUN_LEN(&addr));

    if (res == 0) {
        LOG(NORMAL, "Connected to %s\n", ctx->ctrl_socket_path);

        /* Delete the connect timer */
        timer_del(timer);

        /* Start the write timer */
        timer_add_periodic(&ctx->timer_root, &ctx->ctrl_socket_write_timer, "write",
                           0, 20 * MSEC, ctx, &lspgen_ctrl_write_cb);

        /*
         * Reset write buffer.
         */
        ctx->ctrl_io_buf.start_idx = 0;
        ctx->ctrl_io_buf.idx = 0;

	/*
	 * Reset statistics.
	 */
	ctx->ctrl_stats.octets_sent = 0;
	ctx->ctrl_stats.packets_sent = 0;

        /*
         * Write header before the first packet.
         */
        ctx->ctrl_packet_first = true;

        LOG(NORMAL, "Enqueued %u packets to %s\n", ctx->ctrl_stats.packets_queued, ctx->ctrl_socket_path);
        return;
    }

    close(ctx->ctrl_socket_sockfd);
    ctx->ctrl_socket_sockfd = 0;
    LOG(ERROR, "Error connecting to %s, %s\n", ctx->ctrl_socket_path, strerror(errno));
}
