/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * Link state packet serialization.
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"
#include "hmac_md5.h"

/*
 * Prototypes.
 */
void lspgen_gen_packet_node(lsdb_node_t *);

void
lspgen_gen_packet_header(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet)
{
    unsigned long long sysid;
    uint8_t lsattr;

    /*
     * Reset buffer.
     */
    packet->buf.data = packet->data;
    packet->buf.start_idx = 0;
    packet->buf.idx = 0;
    packet->buf.size = sizeof(packet->data);

    push_be_uint(&packet->buf, 1, 0x83); /* Intradomain Routeing Protocol Discriminator */
    push_be_uint(&packet->buf, 1, 27); /* Length Indicator always 27 for LSPs */
    push_be_uint(&packet->buf, 1, 1); /* Version/Protocol ID Extension */
    push_be_uint(&packet->buf, 1, 0); /* ID Length */

    /* PDU Type */
    if (ctx->topology_id.level == 1) {
        push_be_uint(&packet->buf, 1, ISIS_PDU_L1_LSP);
    }
    if (ctx->topology_id.level == 2) {
        push_be_uint(&packet->buf, 1, ISIS_PDU_L2_LSP);
    }

    push_be_uint(&packet->buf, 1, 1); /* Version */
    push_be_uint(&packet->buf, 1, 0); /* Reserved */
    push_be_uint(&packet->buf, 1, 0); /* Maximum Area Addresses */

    push_be_uint(&packet->buf, 2, 0); /* PDU length */
    push_be_uint(&packet->buf, 2, 0); /* Remaining Lifetime  - will be overwritten during checksum calc */

    /* LSP ID */
    sysid = read_be_uint(node->key.node_id, 6);
    push_be_uint(&packet->buf, 6, sysid); /* System ID */
    push_be_uint(&packet->buf, 1, 0); /* PSN # */
    push_be_uint(&packet->buf, 1, packet->key.id); /* Fragment # */

    push_be_uint(&packet->buf, 4, node->sequence); /* Sequence */
    push_be_uint(&packet->buf, 2, 0); /* Checksum */

    lsattr = 0;
    if (ctx->topology_id.level == 1) {
        lsattr |= 0x01;
    }
    if (ctx->topology_id.level == 2) {
        lsattr |= 0x03;
    }
    if (node->overload) {
        lsattr |= 0x04;
    }
    if (node->attach) {
        lsattr |= 0x08;
    }
    push_be_uint(&packet->buf, 1, lsattr); /* LSP Attributes */
}

/*
 * From tcpdump.org.
 * Creates the OSI Fletcher checksum. See 8473-1, Appendix C, section C.3.
 * The checksum field of the passed PDU does not need to be reset to zero.
 */
uint16_t
calculate_fletcher_cksum(const uint8_t *pptr, int checksum_offset, int length)
{

    int x, y;
    uint32_t mul, c0, c1;
    int idx;

    c0 = 0;
    c1 = 0;

    for (idx = 0; idx < length; idx++) {
        /*
         * Ignore the contents of the checksum field.
         */
        if (idx == checksum_offset || idx == checksum_offset+1) {
            c1 += c0;
            pptr++;
        } else {
            c0 = c0 + *(pptr++);
            c1 += c0;
        }
    }

    c0 = c0 % 255;
    c1 = c1 % 255;

    mul = (length - checksum_offset) * c0;

    x = mul - c0 - c1;
    y = c1 - mul - 1;

    if ( y > 0 ) y++;
    if ( x < 0 ) x--;

    x %= 255;
    y %= 255;

    if (x == 0) x = 255;
    if (y == 0) y = 1;

    return ((x << 8) | (y & 0xff));
}

/*
 * Calculate the size of the authentication TLV to be inserted.
 * Helper for calculating when to start a new packet.
 */
uint32_t
lspgen_calculate_auth_len(lsdb_ctx_t *ctx)
{
   uint8_t auth_len;

   auth_len = 0;
   if (ctx->authentication_key && ctx->authentication_type) {
       if (ctx->authentication_type == ISIS_AUTH_SIMPLE) {
       auth_len = strlen(ctx->authentication_key) + 1 + TLV_OVERHEAD;
       } if (ctx->authentication_type == ISIS_AUTH_MD5) {
       auth_len = 16 + 1 + TLV_OVERHEAD;
       }
   }

   return auth_len;
}

void
lspgen_finalize_packet(lsdb_ctx_t *ctx, lsdb_node_t *node,
                       lsdb_packet_t *packet)
{
    uint16_t checksum;
    uint8_t auth_len;

    /*
     * Generate Authentication TLV
     */
    if (ctx->authentication_key && ctx->authentication_type) {
        auth_len = 0;
        if (ctx->authentication_type == ISIS_AUTH_SIMPLE) {
            auth_len = strlen(ctx->authentication_key);
        } if (ctx->authentication_type == ISIS_AUTH_MD5) {
            auth_len = 16;
        }

        push_be_uint(&packet->buf, 1, ISIS_TLV_AUTH); /* Type */
        push_be_uint(&packet->buf, 1, auth_len+1); /* Length */
        push_be_uint(&packet->buf, 1, ctx->authentication_type);

        if (ctx->authentication_type == ISIS_AUTH_SIMPLE) {
            push_data(&packet->buf, (uint8_t *)ctx->authentication_key, auth_len);
        }
        if (ctx->authentication_type == ISIS_AUTH_MD5) {
            push_be_uint(&packet->buf, 8, 0);
            push_be_uint(&packet->buf, 8, 0);
            /* Update PDU length field. */
            write_be_uint(packet->data+8, 2, packet->buf.idx);
            hmac_md5(packet->buf.data, packet->buf.idx,
                (unsigned char *)ctx->authentication_key, strlen(ctx->authentication_key),
                packet->buf.data+packet->buf.idx-16);
        }
    }

    /*
     * Set remaining lifetime
     */
    if (node->lsp_lifetime) {
        write_be_uint(packet->data+10, 2, node->lsp_lifetime);
    } else {
        write_be_uint(packet->data+10, 2, ctx->lsp_lifetime);
    }

    /*
     * Update PDU length field.
     */
    write_be_uint(packet->data+8, 2, packet->buf.idx);

    /*
     * Calculate Checksum
     */
    write_be_uint(packet->data+24, 2, 0); /* reset checksum field */
    checksum = calculate_fletcher_cksum(packet->data+12, 12, packet->buf.idx-12);
    write_be_uint(packet->data+24, 2, checksum);

}

bool
lsdb_attr_subtlvs_present(struct lsdb_attr_ *attr)
{
    switch (attr->key.attr_type) {
        case ISIS_TLV_EXTD_IPV4_REACH:
            if (attr->key.prefix.adv_sid || attr->key.prefix.adv_tag) {
                return true;
            }
            if ((attr->key.prefix.ext_flag || attr->key.prefix.r_flag || attr->key.prefix.node_flag)) {
                return true;
            }
            break;
        case ISIS_TLV_EXTD_IPV6_REACH:
            if (attr->key.prefix.adv_sid || attr->key.prefix.adv_tag) {
                return true;
            }
            break;
        default:
            break;
    }
    return false;
}

/*
 * Write the IP Prefix TLV subTLVs
 */
void
lspgen_serialize_prefix_subtlv(lsdb_attr_t *attr, io_buffer_t *buf,
                               bool calculate_total_length)
{
    uint32_t total_subtlv_length_idx, subtlv_start_idx;
    uint8_t flags;

    if (calculate_total_length) {
        total_subtlv_length_idx = buf->idx;
        push_be_uint(buf, 1, 0); /* Total subTLV length */
    }

    subtlv_start_idx = buf->idx;
    if (attr->key.prefix.adv_sid) {
        push_be_uint(buf, 1, ISIS_SUBTLV_PREFIX_SID); /* subTLV type */
        push_be_uint(buf, 1, 0); /* subTLV length */

        flags = 0;
        if (attr->key.prefix.r_flag) {
            flags |= 0x80;
        }
        if (attr->key.prefix.node_flag) {
            flags |= 0x40;
        }
        if (attr->key.prefix.no_php_flag) {
            flags |= 0x20;
        }
        if (attr->key.prefix.exp_null_flag) {
            flags |= 0x10;
        }
        if (attr->key.prefix.value_flag) {
            flags |= 0x08;
        }
        if (attr->key.prefix.local_flag) {
            flags |= 0x04;
        }
        push_be_uint(buf, 1, flags); /* flags */

        push_be_uint(buf, 1, attr->key.prefix.sid_algo); /* algo */
        push_be_uint(buf, 4, attr->key.prefix.sid); /* SID Index */

        buf->data[subtlv_start_idx+1] = buf->idx - subtlv_start_idx - 2; /* Update subtlv length */
    }

    subtlv_start_idx = buf->idx;
    if (attr->key.prefix.adv_tag) {
        push_be_uint(buf, 1, ISIS_SUBTLV_PREFIX_TAG); /* subTLV type */
        push_be_uint(buf, 1, 0); /* subTLV length */
        push_be_uint(buf, 4, attr->key.prefix.tag); /* Tag */

        buf->data[subtlv_start_idx+1] = buf->idx - subtlv_start_idx - 2; /* Update subtlv length */
    }

    /*
     * The IPv4 Prefix TLV has limited space for flags. Generate them as subTLV if required.
     */
    if (attr->key.attr_type == ISIS_TLV_EXTD_IPV4_REACH &&
        (attr->key.prefix.ext_flag ||
         attr->key.prefix.r_flag ||
         attr->key.prefix.node_flag)) {

        subtlv_start_idx = buf->idx;
        push_be_uint(buf, 1, ISIS_SUBTLV_PREFIX_FLAG); /* subTLV type */
        push_be_uint(buf, 1, 0); /* subTLV length */

        flags = 0;
        if (attr->key.prefix.ext_flag) {
            flags |= 0x80;
        }
        if (attr->key.prefix.r_flag) {
            flags |= 0x40;
        }
        if (attr->key.prefix.node_flag) {
            flags |= 0x20;
        }
        push_be_uint(buf, 1, flags); /* flags */

        buf->data[subtlv_start_idx+1] = buf->idx - subtlv_start_idx - 2; /* Update subtlv length */
    }

    if (calculate_total_length) {
        /*
        * Update total subTLV length
        */
        buf->data[total_subtlv_length_idx] = buf->idx - total_subtlv_length_idx - 1;
    }
}

/*
 * Serialize a attribute into a buffer.
 *
 * This is used in two places.
 *  1) When an attribute gets added for size measurement.
 *  2) When the actual link-state packets gets built.
 */
void
lspgen_serialize_attr(lsdb_attr_t *attr, io_buffer_t *buf)
{
    uint32_t metric, mask;
    uint8_t attr_len, flags;
    bool subtlv_present;

    subtlv_present = lsdb_attr_subtlvs_present(attr);

    switch (attr->key.attr_type) {
        case ISIS_TLV_AREA:
            attr_len = (attr->key.area.len+7)/8;
            push_be_uint(buf, 1, attr_len); /* Area Length in bytes */
            push_data(buf, attr->key.area.address, attr_len);
            break;
        case ISIS_TLV_PROTOCOLS:
            push_be_uint(buf, 1, attr->key.protocol);
            break;
        case ISIS_TLV_IS_REACH:
            push_be_uint(buf, 1, 0); /* virtual */
	    metric = attr->key.link.metric;
	    if (metric > 63) {
		metric = 63; /* limit metric to 6 bits */
	    }
            push_be_uint(buf, 1, metric); /* default metric */
            push_be_uint(buf, 1, 0x80); /* delay metric */
            push_be_uint(buf, 1, 0x80); /* expense metric */
            push_be_uint(buf, 1, 0x80); /* error metric */
            push_data(buf, attr->key.link.remote_node_id, 7);
	    break;
        case ISIS_TLV_EXTD_IS_REACH:
            push_data(buf, attr->key.link.remote_node_id, 7);
            push_be_uint(buf, 3, attr->key.link.metric); /* Metric */
            push_be_uint(buf, 1, 0); /* subTLV length */
            break;
        case ISIS_TLV_IPV4_ADDR:
            push_data(buf, attr->key.ipv4_addr, 4);
            break;
        case ISIS_TLV_IPV6_ADDR:
            push_data(buf, attr->key.ipv6_addr, 16);
            break;
        case ISIS_TLV_HOSTNAME:
            attr_len = strnlen(attr->key.hostname, sizeof(attr->key.hostname));
            push_data(buf, (uint8_t *)attr->key.hostname, attr_len);
            break;
        case ISIS_TLV_INT_IPV4_REACH: /* fall through */
        case ISIS_TLV_EXT_IPV4_REACH:
	    metric = attr->key.prefix.metric;
	    if (metric > 63) {
		metric = 63; /* limit metric to 6 bits */
	    }
	    flags = metric;
            if (attr->key.prefix.updown_flag) {
                flags |= 0x80;
            }
            push_be_uint(buf, 1, flags); /* default metric */
            push_be_uint(buf, 1, 0x80); /* delay metric */
            push_be_uint(buf, 1, 0x80); /* expense metric */
            push_be_uint(buf, 1, 0x80); /* error metric */
            push_data(buf, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, 4);
	    mask = 0xffffffff;
	    /* convert prefix length to mask */
	    mask &= ~((1 << ((32 - attr->key.prefix.ipv4_prefix.len)))-1);
	    push_be_uint(buf, 4, mask);
	    break;
        case ISIS_TLV_EXTD_IPV4_REACH:
            push_be_uint(buf, 4, attr->key.prefix.metric); /* Metric */
            flags = attr->key.prefix.ipv4_prefix.len & 0x3f;
            if (attr->key.prefix.updown_flag) {
                flags |= 0x80;
            }
            if (subtlv_present) {
                flags |= 0x40; /* subTLVs present */
            }
            push_be_uint(buf, 1, flags); /* Flags */
            attr_len = (attr->key.prefix.ipv4_prefix.len+7)/8;
            push_data(buf, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, attr_len);

            /* Generate subTLVs */
            if (subtlv_present) {
                lspgen_serialize_prefix_subtlv(attr, buf, true);
            }
            break;
        case ISIS_TLV_EXTD_IPV6_REACH:
            push_be_uint(buf, 4, attr->key.prefix.metric); /* Metric */
            flags = 0;
            if (attr->key.prefix.updown_flag) {
                flags |= 0x80; /* Up/Down */
            }
            if (attr->key.prefix.ext_flag) {
                flags |= 0x40; /* External */
            }
            if (subtlv_present) {
                flags |= 0x20; /* subTLV present */
            }
            push_be_uint(buf, 1, flags); /* Flags */
            push_be_uint(buf, 1, attr->key.prefix.ipv6_prefix.len); /* Prefix len */
            attr_len = (attr->key.prefix.ipv6_prefix.len+7)/8;
            push_data(buf, attr->key.prefix.ipv6_prefix.address, attr_len);

            /* Generate subTLVs */
            if (subtlv_present) {
                lspgen_serialize_prefix_subtlv(attr, buf, true);
            }
            break;
        case ISIS_TLV_CAP:
            push_data(buf, attr->key.cap.router_id, 4);
            flags = 0;
            if (attr->key.cap.d_flag) {
                flags |= 0x02;
            }
            if (attr->key.cap.s_flag) {
                flags |= 0x01;
            }
            push_be_uint(buf, 1, flags); /* Flags */
            if (attr->key.cap.srgb_base && attr->key.cap.srgb_range) {
                push_be_uint(buf, 1, ISIS_SUBTLV_CAP_SR); /* subTLV Type */
                push_be_uint(buf, 1, 9); /* *subTLV Length */
                flags = 0;
                if (attr->key.cap.mpls_ipv4_flag) {
                    flags |= 0x80;
                }
                if (attr->key.cap.mpls_ipv6_flag) {
                    flags |= 0x40;
                }
                push_be_uint(buf, 1, flags);
                push_be_uint(buf, 3, attr->key.cap.srgb_range);
                push_be_uint(buf, 1, 1); /* SID Type Label */
                push_be_uint(buf, 1, 3); /* SID Type Length */
                push_be_uint(buf, 3, attr->key.cap.srgb_base);
            }
            break;
        case ISIS_TLV_BINDING:
            flags = 0;
            if (attr->key.prefix.family_flag) {
                flags |= 0x80;
            }
            if (attr->key.prefix.s_flag) {
                flags |= 0x20;
            }
            if (attr->key.prefix.updown_flag) {
                flags |= 0x10;
            }
            push_be_uint(buf, 1, flags); /* Flags */
            push_be_uint(buf, 1, 0); /* Reserved */
            push_be_uint(buf, 2, attr->key.prefix.range); /* Range */
            if (attr->key.prefix.family_flag) {
                push_be_uint(buf, 1, attr->key.prefix.ipv6_prefix.len);
                attr_len = (attr->key.prefix.ipv6_prefix.len+7)/8;
                push_data(buf, attr->key.prefix.ipv6_prefix.address, attr_len);
            } else {
                push_be_uint(buf, 1, attr->key.prefix.ipv4_prefix.len);
                attr_len = (attr->key.prefix.ipv4_prefix.len+7)/8;
                push_data(buf, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, attr_len);
            }
            lspgen_serialize_prefix_subtlv(attr, buf, false);
            break;
        default:
            LOG(ERROR, "No packet serializer for attr %d\n", attr->key.attr_type);
            break;
    }
}

/*
 * Update length field of last TLV written to the buffer.
 */
void
lspgen_update_tlv_length(io_buffer_t *buf, uint32_t tlv_start_idx)
{
    uint8_t tlv_len;

    tlv_len = buf->idx - tlv_start_idx - 2;
    write_be_uint(buf->data+tlv_start_idx+1, 1, tlv_len);
}

/*
 * Return the space left in this TLV.
 */
uint32_t
lspgen_calculate_tlv_space(io_buffer_t *buf, uint32_t tlv_start_idx)
{
    uint8_t tlv_len;

    tlv_len = buf->idx - tlv_start_idx - 2;
    return 255 - tlv_len;
}

/*
 * Lookup / Create a fresh packet based on the id.
 */
lsdb_packet_t *
lspgen_add_packet(lsdb_ctx_t *ctx, lsdb_node_t *node, uint32_t id)
{
    struct lsdb_packet_ packet_template;
    struct lsdb_packet_ *packet;
    dict_insert_result result;
    void **p;

    packet_template.key.id = id;
    p = dict_search(node->packet_dict, &packet_template.key);
    if (!p) {

        packet = calloc(1, sizeof(struct lsdb_packet_));
        if (!packet) {
            return NULL;
        }

        /*
        * Insert packet into dictionary hanging off a node.
        */
        packet->key.id = id;
        result = dict_insert(node->packet_dict, &packet->key);
        if (!result.inserted) {
            free(packet);
            return NULL;
        }
        *result.datum_ptr = packet;

        /*
        * Enqueue the packet to the packet change list.
        */
        CIRCLEQ_INSERT_TAIL(&ctx->packet_change_qhead, packet, packet_change_qnode);
        packet->on_change_list = true;
	ctx->ctrl_stats.packets_queued++;

        /*
        * Parent
        */
        packet->parent = node;

        /*
        * Write header for link-state packet.
        */
        lspgen_gen_packet_header(ctx, node, packet);

        return packet;
    }

    return *p;
}

/*
 * Refresh timer has expired. Bump the sequence number of the node and rebuild all fragments.
 */
void
lspgen_refresh_cb (timer_s *timer)
{
    struct lsdb_node_ *node;
    struct lsdb_ctx_ *ctx;

    node = timer->data;
    ctx = node->ctx;

    node->sequence++;
    LOG(LSDB, "Refresh LSP for %s, sequence 0x%0x\n", lsdb_format_node(node), node->sequence);

    lspgen_gen_packet_node(node);

    /*
     * Set up a ctrl session to drain the refreshed LSPs.
     */
    if (ctx->ctrl_socket_path) {

	if (!ctx->ctrl_socket_connect_timer) {
	    timer_add_periodic(&ctx->timer_root, &ctx->ctrl_socket_connect_timer,
			       "connect", 1, 0, ctx, &lspgen_ctrl_connect_cb);
	}
    }
}

/*
 * The refresh interval is lsp_lifetime minus 300 seconds.
 * Ensure that it does not go below 60 secs.
 */
unsigned int
lspgen_refresh_interval (lsdb_ctx_t *ctx)
{
    int refresh;

    refresh = ctx->lsp_lifetime - 300;
    if (refresh < 60) {
	refresh = 60;
    }

    return refresh;
}

/*
 * Walk the graph of the LSDB and serialize packets.
 */
void
lspgen_gen_packet_node(lsdb_node_t *node)
{
    lsdb_ctx_t *ctx;
    struct lsdb_packet_ *packet;
    struct lsdb_attr_ *attr;
    dict_itor *itor;
    uint32_t id, last_attr, tlv_start_idx, min_len;

    ctx = node->ctx;

    packet = NULL;
    id = 0;
    last_attr = 0;
    tlv_start_idx = 0;

    /*
     * Flush old serialized packets.
     */
    dict_clear(node->packet_dict, lsdb_free_packet);

    if (!node->attr_dict) {
        /*
         * No attributes. This is a purge.
         */
        packet = lspgen_add_packet(ctx, node, id);
        lspgen_finalize_packet(ctx, node, packet);
        return;
    }

    /*
     * Walk the node attributes.
     */
    itor = dict_itor_new(node->attr_dict);
    if (!itor) {
        return;
    }

    /*
     * Node DB empty ?
     */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG(ERROR, "No Attributes for node %s\n", lsdb_format_node(node));
        return;
    }

    /*
     * Start refresh timer.
     */
    if (ctx->ctrl_socket_path) {
	timer_add_periodic(&ctx->timer_root, &node->refresh_timer, "refresh",
			   lspgen_refresh_interval(ctx), 0, node, &lspgen_refresh_cb);
    }

    do {
        attr = *dict_itor_datum(itor);

        /*
         * Space left in this packet ?
         */
        min_len = lspgen_calculate_auth_len(ctx);
        min_len += attr->size + TLV_OVERHEAD;
        if (packet && packet->buf.idx > (1465-min_len)) {

            /*
            * No space left. Finalize this packet.
            */
            lspgen_finalize_packet(ctx, node, packet);
            packet = NULL;

            id++;
            if (id > 255) {
                dict_itor_free(itor);
                LOG(ERROR, "Exhausted fragments for node %s\n", lsdb_format_node(node));
                return;
            }
        }

        /*
         * Need a fresh packet ?
         */
        if (!packet) {
            packet = lspgen_add_packet(ctx, node, id);
            tlv_start_idx = packet->buf.idx;
        }

        /*
         * Encode node attributes.
         */

        /*
         * Start a fresh TLV ?
         */
        if ((last_attr != attr->key.attr_type) ||
            (lspgen_calculate_tlv_space(&packet->buf, tlv_start_idx) < attr->size) ||
	    attr->key.start_tlv) {
            tlv_start_idx = packet->buf.idx;
            push_be_uint(&packet->buf, 1, attr->key.attr_type); /* Type */
            push_be_uint(&packet->buf, 1, 0); /* Length */
        }

        lspgen_serialize_attr(attr, &packet->buf);
        lspgen_update_tlv_length(&packet->buf, tlv_start_idx);

        last_attr = attr->key.attr_type;

    } while (dict_itor_next(itor));

    lspgen_finalize_packet(ctx, node, packet);
    dict_itor_free(itor);
}

/*
 * Walk the graph of the LSDB and serialize packets.
 */
void
lspgen_gen_packet(lsdb_ctx_t *ctx)
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

	/*
	 * Init per-packet tree for this node.
	 */
	if (!node->packet_dict) {
	    node->packet_dict = hb_dict_new((dict_compare_func)lsdb_compare_packet);
	}

	/*
         * Generate the link-state packets for this node.
         */
        lspgen_gen_packet_node(node);

    } while (dict_itor_next(itor));

    dict_itor_free(itor);

    /*
     * Distribute expiration of refresh timer over time.
     */
    timer_smear_bucket(&ctx->timer_root, lspgen_refresh_interval(ctx), 0);
}
