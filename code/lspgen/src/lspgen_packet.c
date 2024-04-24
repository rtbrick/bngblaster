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
#include "lspgen_ospf.h"
#include "hmac_md5.h"

/*
 * Prototypes.
 */
void lspgen_gen_packet_node(lsdb_node_t *);
void lspgen_serialize_ospf2_state(lsdb_attr_t *, lsdb_packet_t *, uint16_t);
void lspgen_serialize_ospf3_state(lsdb_attr_t *, lsdb_packet_t *, uint16_t);

void
lspgen_gen_isis_packet_header(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet)
{
    struct io_buffer_ *buf;
    unsigned long long sysid;
    uint8_t lsattr;

    /*
     * Reset buffer.
     */
    buf = &packet->buf[0];
    buf->data = packet->data;
    buf->start_idx = 0;
    buf->idx = 0;
    buf->size = sizeof(packet->data);

    push_be_uint(buf, 1, 0x83); /* Intradomain Routeing Protocol Discriminator */
    push_be_uint(buf, 1, 27); /* Length Indicator always 27 for LSPs */
    push_be_uint(buf, 1, 1); /* Version/Protocol ID Extension */
    push_be_uint(buf, 1, 0); /* ID Length */

    /* PDU Type */
    if (ctx->topology_id.level == 1) {
        push_be_uint(buf, 1, ISIS_PDU_L1_LSP);
    }
    if (ctx->topology_id.level == 2) {
        push_be_uint(buf, 1, ISIS_PDU_L2_LSP);
    }

    push_be_uint(buf, 1, 1); /* Version */
    push_be_uint(buf, 1, 0); /* Reserved */
    push_be_uint(buf, 1, 0); /* Maximum Area Addresses */

    push_be_uint(buf, 2, 0); /* PDU length */
    push_be_uint(buf, 2, 0); /* Remaining Lifetime  - will be overwritten during checksum calc */

    /* LSP ID */
    sysid = read_be_uint(node->key.node_id, 6);
    push_be_uint(buf, 6, sysid); /* System ID */
    push_be_uint(buf, 1, 0); /* PSN # */
    push_be_uint(buf, 1, packet->key.id); /* Fragment # */

    push_be_uint(buf, 4, node->sequence); /* Sequence */
    push_be_uint(buf, 2, 0); /* Checksum */

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
    push_be_uint(buf, 1, lsattr); /* LSP Attributes */
}

void
lspgen_gen_packet_header(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet)
{
    switch (ctx->protocol_id) {
        case PROTO_ISIS:
            lspgen_gen_isis_packet_header(ctx, node, packet);
            break;
        case PROTO_OSPF2:
            break;
        case PROTO_OSPF3:
            break;
        default:
	        LOG_NOARG(ERROR, "Unknown protocol\n");
    }
}

static uint32_t
_checksum(void *buf, ssize_t len)
{
    uint32_t result = 0;
    uint16_t *cur = buf;
    while (len > 1) {
        result += *cur++;
        len -= 2;
    }
    /*  Add left-over byte, if any */
    if(len) {
        result += *(uint8_t*)cur;
    }
    return result;
}

static uint32_t
_fold(uint32_t sum)
{
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum;
}

uint16_t
calculate_cksum(uint8_t *buf, uint16_t len)
{
    return ~_fold(_checksum(buf, len));
}

/*
 * Calculate an ospf3 checksum including the pseudoheader as per
 *   https://www.rfc-editor.org/rfc/rfc2460#page-27
 *
 * Expects the IPv6 header at the beginning of buf and a correctly set packet length field.
 */
uint16_t
calculate_ospf3_cksum(uint8_t *buf, uint16_t len)
{
    uint32_t cksum;
    uint8_t protocol[4] = {0, 0, 0, 89} ; /* Protocol pseudoheader */

    if (len < 40) {
	return 0;
    }

    cksum = 0;
    cksum += _checksum(buf+8, 16);   /* source-ip */
    cksum += _checksum(buf+24, 16);  /* destination-ip */
    cksum += _checksum(buf+4, 2);    /* packet-length */
    cksum += _checksum(protocol, 4); /* protocol */

    cksum += _checksum(buf+40, len-40);

    return ~_fold(cksum);
}

/*
 * Calculate the size of the authentication data to be inserted.
 * Helper for calculating when to start a new packet.
 */
uint32_t
lspgen_calculate_auth_len(lsdb_ctx_t *ctx)
{
   uint8_t auth_len;

   auth_len = 0;
   switch (ctx->protocol_id) {
   case PROTO_ISIS:
       if (ctx->authentication_key && ctx->authentication_type) {
	   if (ctx->authentication_type == ISIS_AUTH_SIMPLE) {
	       auth_len = strlen(ctx->authentication_key) + 1 + TLV_OVERHEAD;
	   } if (ctx->authentication_type == ISIS_AUTH_MD5) {
	       auth_len = 16 + 1 + TLV_OVERHEAD;
	   }
       }
       break;

       /*
	* BNG Blaster computes the authentication trailer for OSPF2 and OSPF3
	*/
   case PROTO_OSPF2: /* fall through */
   case PROTO_OSPF3: /* fall through */
   default:
       break;
   }
   return auth_len;
}

void
lspgen_finalize_isis_packet(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet)
{
    struct io_buffer_ *buf;
    uint16_t checksum, lsp_lifetime;
    uint8_t auth_len;

    buf = &packet->buf[0];

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

        push_be_uint(buf, 1, ISIS_TLV_AUTH); /* Type */
        push_be_uint(buf, 1, auth_len+1); /* Length */
        push_be_uint(buf, 1, ctx->authentication_type);

        if (ctx->authentication_type == ISIS_AUTH_SIMPLE) {
            push_data(buf, (uint8_t *)ctx->authentication_key, auth_len);
        }
        if (ctx->authentication_type == ISIS_AUTH_MD5) {
            push_be_uint(buf, 8, 0);
            push_be_uint(buf, 8, 0);
            /* Update PDU length field. */
            write_be_uint(packet->data+8, 2, buf->idx);
            hmac_md5(buf->data, buf->idx,
                (unsigned char *)ctx->authentication_key, strlen(ctx->authentication_key),
                buf->data+buf->idx-16);
        }
    }

    /*
     * Set remaining lifetime
     */
    if (node->lsp_lifetime) {
	lsp_lifetime = node->lsp_lifetime;
    } else {
	lsp_lifetime = ctx->lsp_lifetime;
    }
    if (ctx->purge) {
	lsp_lifetime = 0;
    }
    write_be_uint(packet->data+10, 2, lsp_lifetime);

    /*
     * Update PDU length field.
     */
    write_be_uint(packet->data+8, 2, buf->idx);

    /*
     * Calculate Checksum
     */
    write_be_uint(buf->data+24, 2, 0); /* reset checksum field */
    checksum = calculate_fletcher_checksum(buf->data+12, 12, buf->idx-12);
    write_be_uint(buf->data+24, 2, checksum);
    if (log_id[DEBUG].enable && validate_fletcher_checksum(buf->data+12, buf->idx-12)) {
	    LOG(DEBUG, "Checksum error 0x%04x\n", checksum);
    }
}

/*
 * Close all Message levels that the serializer may have left open.
 */
uint16_t
lspgen_close_all_message_levels (lsdb_packet_t *packet)
{
    uint16_t state;

    state = 0;
    if (packet->prev_attr_cp[0]) {
	state |= CLOSE_LEVEL0;
    }
    if (packet->prev_attr_cp[1]) {
	state |= CLOSE_LEVEL1;
    }
    if (packet->prev_attr_cp[2]) {
	state |= CLOSE_LEVEL2;
    }
    if (packet->prev_attr_cp[3]) {
	state |= CLOSE_LEVEL3;
    }

    return state;
}

void
lspgen_finalize_packet(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet)
{
    switch (ctx->protocol_id) {
    case PROTO_ISIS:
	lspgen_finalize_isis_packet(ctx, node, packet);
	break;
    case PROTO_OSPF2:
	lspgen_serialize_ospf2_state(NULL, packet, lspgen_close_all_message_levels(packet));
	break;
    case PROTO_OSPF3:
	lspgen_serialize_ospf3_state(NULL, packet, lspgen_close_all_message_levels(packet));
	break;
    default:
	LOG_NOARG(ERROR, "Unknown protocol\n");
    }
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
 * Serialize an IS-IS attribute into a packet buffer.
 */
void
lspgen_serialize_isis_attr(lsdb_attr_t *attr, lsdb_packet_t *packet)
{
    uint32_t metric, mask;
    uint8_t attr_len, flags;
    bool subtlv_present;
    io_buffer_t *buf;

    buf = &packet->buf[0];

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
                flags |= 0x40; /* Sub-TLVs present */
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
 * Inititialize a next level buffer to the remnants of the passed in buffer.
 * This gives us nice hierarchical buffers with boundary protection.
 */
void
lspgen_propagate_buffer_down (lsdb_packet_t *packet, uint level)
{
    struct io_buffer_ *cur, *next;

    /* boundary protection */
    if (level >= MAX_MSG_LEVEL - 1) {
	return;
    }

    cur = &packet->buf[level];
    next = &packet->buf[level+1];

    next->data = cur->data + cur->idx;
    next->size = cur->size - cur->idx;
    next->idx = 0;
    next->start_idx = 0;
}

/*
 * Propagate the buffer index one level up.
 */
void
lspgen_propagate_buffer_up (lsdb_packet_t *packet, uint level)
{
    struct io_buffer_ *cur, *prev;

    /* boundary protection */
    if (level == 0 || level >= MAX_MSG_LEVEL) {
	return;
    }

    cur = &packet->buf[level];
    prev = &packet->buf[level-1];

    prev->idx += cur->idx;
    cur->data += cur->idx;
    cur->size -= cur->idx;
    cur->idx = 0;
}

char *
lspgen_format_serializer_state (uint16_t state)
{
    static char buf[128];
    int len;
    bool first, close;

    len = 0;
    close = false;
    buf[0] = 0;

    /* some close bits set ? */
    first = true;
    if (state & (CLOSE_LEVEL0|CLOSE_LEVEL1|CLOSE_LEVEL2|CLOSE_LEVEL3)) {
	close = true;
	len += snprintf(buf+len, sizeof(buf)-len, "close: ");
	if (state & CLOSE_LEVEL0) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL0", first ? "" : ", ");
	    first =false;
	}
	if (state & CLOSE_LEVEL1) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL1", first ? "" : ", ");
	    first =false;
	}
	if (state & CLOSE_LEVEL2) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL2", first ? "" : ", ");
	    first =false;
	}
	if (state & CLOSE_LEVEL3) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL3", first ? "" : ", ");
	    first =false;
	}
    }

    /* some open bits set ? */
    first = true;
    if (state & (OPEN_LEVEL0|OPEN_LEVEL1|OPEN_LEVEL2|OPEN_LEVEL3)) {
	len += snprintf(buf+len, sizeof(buf)-len, "%sopen: ", close ? ", " : "");
	if (state & OPEN_LEVEL0) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL0", first ? "" : ", ");
	    first =false;
	}
	if (state & OPEN_LEVEL1) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL1", first ? "" : ", ");
	    first =false;
	}
	if (state & OPEN_LEVEL2) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL2", first ? "" : ", ");
	    first =false;
	}
	if (state & OPEN_LEVEL3) {
	    len += snprintf(buf+len, sizeof(buf)-len, "%sL3", first ? "" : ", ");
	    first =false;
	}
    }

    return buf;
}

uint16_t
lspgen_get_ospf_age(lsdb_node_t *node)
{
    lsdb_ctx_t *ctx;

    ctx = node->ctx;

    if (ctx->purge) {
	return 3600;
    }

    return 1;
}

/*
 * Fill a buffer with zeros up to the next 32bit boundary.
 */
void
push_pad4(io_buffer_t *buf)
{
    uint pad_octets;

    pad_octets = PAD4(buf->idx) - buf->idx;
    push_be_uint(buf, pad_octets, 0);
}

void
lspgen_serialize_ospf2_state(lsdb_attr_t *attr, lsdb_packet_t *packet, uint16_t state)
{
    lsdb_ctx_t *ctx;
    lsdb_node_t *node;
    io_buffer_t *buf0, *buf1, *buf2, *buf3;
    uint16_t attr_len, checksum;
    uint32_t router_id, mask;

    node = packet->parent;
    ctx = node->ctx;

    buf0 = &packet->buf[0];
    buf1 = &packet->buf[1];
    buf2 = &packet->buf[2];
    buf3 = &packet->buf[3];

    LOG(PACKET, "  %s\n", lspgen_format_serializer_state(state));

    /* close Level 3 */
    if (state & CLOSE_LEVEL3) {
	switch (packet->prev_attr_cp[3]) {
	case OSPF_SUBTLV_PREFIX_SID:
	    write_be_uint(buf3->data+2, 2, buf3->idx-4); /* Update length */
	    push_pad4(buf3);
	    break;
	default:
	    break;
	}

	lspgen_propagate_buffer_up(packet, 3);
    }

    /* close Level 2 */
    if (state & CLOSE_LEVEL2) {
	switch (packet->prev_attr_cp[2]) {
	case OSPF_TLV_EXTENDED_PREFIX_RANGE: /* fall through */
	case OSPF_TLV_EXTENDED_PREFIX:
	case OSPF_TLV_SID_LABEL_RANGE:
	    write_be_uint(buf2->data+2, 2, buf2->idx-4); /* Update length */
	    push_pad4(buf2);
	default:
	    break;
	}

	lspgen_propagate_buffer_up(packet, 2);
    }

    /* close Level 1 */
    if (state & CLOSE_LEVEL1) {
	switch (packet->prev_attr_cp[1]) {
	case OSPF_LSA_ROUTER:
	case OSPF_LSA_EXTERNAL:
	case OSPF_LSA_OPAQUE_AREA_RI:
	case OSPF_LSA_OPAQUE_AREA_EP:
	    inc_be_uint(buf0->data+20+24, 4); /* Update #LSAs */

	    write_be_uint(buf1->data+18, 2, buf1->idx); /* Update length */

	    write_be_uint(buf1->data+16, 2, 0); /* reset checksum field */
	    checksum = calculate_fletcher_checksum(buf1->data+2, 14, buf1->idx-2);
	    write_be_uint(buf1->data+16, 2, checksum); /* LSA Checksum */
	    if (log_id[DEBUG].enable && validate_fletcher_checksum(buf1->data+2, buf1->idx-2)) {
		    LOG(DEBUG, "Checksum error 0x%04x\n", checksum);
	    }
	    break;
	default:
	    break;
	}

	lspgen_propagate_buffer_up(packet, 1);
    }

    /* close Level 0 */
    if (state & CLOSE_LEVEL0) {
	switch (packet->prev_attr_cp[0]) {
	    case OSPF_MSG_LSUPDATE:
		write_be_uint(buf0->data+20+2, 2, buf0->idx - 20); /* Packet length */
		write_be_uint(buf0->data+20+12, 2, calculate_cksum(buf0->data+20, buf0->idx-20)); /* Checksum */

		write_be_uint(buf0->data+2, 2, buf0->idx); /* IP Total length */
		write_le_uint(buf0->data+10, 2, calculate_cksum(buf0->data, 20)); /* IP header checksum */
		break;
	default:
	    break;
	}
    }

    /* open Level 0 */
    if (state & OPEN_LEVEL0) {

	switch(attr->key.attr_cp[0]) {
	case OSPF_MSG_LSUPDATE:

	    /* IPv4 header */
	    push_be_uint(buf0, 1, 0x45); /* Version, Header Length */
	    push_be_uint(buf0, 1, 0xc0); /* TOS */
	    push_be_uint(buf0, 2, 0); /* Total length - will be overwritten later */
	    push_be_uint(buf0, 2, 0); /* Identification */
	    push_be_uint(buf0, 2, 0); /* Flags & Fragment offset */
	    push_be_uint(buf0, 1, 255); /* TTL */
	    push_be_uint(buf0, 1, 89); /* Protocol */
	    push_be_uint(buf0, 2, 0); /* Checksum - will be overwritten later */
	    push_data(buf0, ctx->root_node_id, 4); /* Source Address */
	    push_be_uint(buf0, 4, 0xe0000005); /* Destination Address */

	    /* OSPFv2 header */
	    push_be_uint(buf0, 1, 2); /* Version */
	    push_be_uint(buf0, 1, 4); /* Msg: LS-Update  */
	    push_be_uint(buf0, 2, 0); /* Packet length - will be overwritten later */

	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf0, 4, router_id); /* Router ID */
	    push_be_uint(buf0, 4, ctx->topology_id.area); /* Area ID */

	    push_be_uint(buf0, 2, 0); /* Checksum - will be overwritten later */

	    push_be_uint(buf0, 2, 0); /* Authentication Type */
	    push_be_uint(buf0, 8, 0); /* Authentication */

	    push_be_uint(buf0, 4, 0); /* # LSAs - will be overwritten later */
	    break;
	default:
            LOG(ERROR, "No Level 0 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[0]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 0);
    }

    /* open Level 1 */
    if (state & OPEN_LEVEL1) {

	switch(attr->key.attr_cp[1]) {
	case OSPF_LSA_ROUTER:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 1, 0); /* Options */
	    push_be_uint(buf1, 1, 1); /* LS-Type: Router-LSA  */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Link State ID */
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */

	    push_be_uint(buf1, 1, 0x02); /* Flags, E */
	    push_be_uint(buf1, 1, 0);
	    push_be_uint(buf1, 2, 0); /* # links - will be overwritten later */
	    break;

	case OSPF_LSA_EXTERNAL:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 1, 0); /* Options */
	    push_be_uint(buf1, 1, 5); /* LS-Type  */
	    push_data(buf1, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, 4); /* Link State ID */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */

            mask = 0xffffffff;
            /* convert prefix length to mask */
            mask &= ~((1 << ((32 - attr->key.prefix.ipv4_prefix.len)))-1);
            push_be_uint(buf1, 4, mask); /* Network Mask */

	    push_be_uint(buf1, 1, 0x80); /* E2 */
            push_be_uint(buf1, 3, attr->key.prefix.metric); /* Metric */
	    push_be_uint(buf1, 4, 0); /* Forwarding Address */
	    push_be_uint(buf1, 4, 0); /* External Route Tag */
	    break;

	case OSPF_LSA_OPAQUE_AREA_RI:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 1, 0); /* Options */
	    push_be_uint(buf1, 1, 10); /* LS-Type  */
	    push_be_uint(buf1, 1, 4); /* Opaque Type: Router-Information */
	    push_be_uint(buf1, 3, 0); /* Opaque subtype  */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */
	    break;

	case OSPF_LSA_OPAQUE_AREA_EP:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 1, 0); /* Options */
	    push_be_uint(buf1, 1, 10); /* LS-Type  */
	    push_be_uint(buf1, 1, 7); /* Opaque Type: Extended Prefix */
	    push_be_uint(buf1, 3, 0); /* Opaque subtype  */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */
	    break;

	default:
            LOG(ERROR, "No Level 1 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[1]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 1);
    }

    /*
     * If users wants to generate purges encoding stops at level 1.
     */
    if (ctx->purge) {
	return;
    }

    /* open Level 2 */
    if (state & OPEN_LEVEL2) {
	switch(attr->key.attr_cp[2]) {
	case OSPF_ROUTER_LSA_LINK_PTP:
	    push_be_uint(buf2, 4, read_be_uint(attr->key.link.remote_node_id, 4)); /* Link ID */
	    push_be_uint(buf2, 4, read_be_uint(attr->key.link.local_link_id, 4)); /* Link Data */
	    push_be_uint(buf2, 1, 1); /* Type ptp */
	    push_be_uint(buf2, 1, 0); /* #TOS */
	    push_be_uint(buf2, 2, attr->key.link.metric); /* metric */

	    inc_be_uint(buf1->data+22, 2); /* Update #links */
	    break;

	case OSPF_ROUTER_LSA_LINK_STUB:
            push_data(buf2, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, 4); /* Link ID */
            mask = 0xffffffff;
            /* convert prefix length to mask */
            mask &= ~((1 << ((32 - attr->key.prefix.ipv4_prefix.len)))-1);
            push_be_uint(buf2, 4, mask); /* Link Data */
	    push_be_uint(buf2, 1, 3); /* Type stub */
	    push_be_uint(buf2, 1, 0); /* #TOS */
	    push_be_uint(buf2, 2, attr->key.prefix.metric); /* metric */

	    inc_be_uint(buf1->data+22, 2); /* Update #links */
	    break;

	case OSPF_TLV_HOSTNAME:
	    attr_len = strnlen(attr->key.hostname, sizeof(attr->key.hostname));
	    if (attr_len) {
		push_be_uint(buf2, 2, 7); /* Type */
		push_be_uint(buf2, 2, attr_len); /* Length */
		push_data(buf2, (uint8_t *)attr->key.hostname, attr_len);
		push_pad4(buf2);
	    }
	    break;

	case OSPF_TLV_SID_LABEL_RANGE:
	    if (attr->key.cap.srgb_base && attr->key.cap.srgb_range) {
		push_be_uint(buf2, 2, 9); /* Type */
		push_be_uint(buf2, 2, 0); /* Length - will be overwritten later */
		push_be_uint(buf2, 3, attr->key.cap.srgb_range); /* Range size */
		push_be_uint(buf2, 1, 0); /* Reserved */

		/* XXX Move this to level 3 */
		push_be_uint(buf2, 2, 1); /* SID Type Label */
		push_be_uint(buf2, 2, 3); /* SID Type Length */
		push_be_uint(buf2, 3, attr->key.cap.srgb_base);
		push_pad4(buf2);
	    }
	    break;

	case OSPF_TLV_EXTENDED_PREFIX_RANGE:
	    push_be_uint(buf2, 2, 2); /* Type */
	    push_be_uint(buf2, 2, 0); /* Length - will be overwritten later */
	    push_be_uint(buf2, 1, attr->key.prefix.ipv4_prefix.len);
	    push_be_uint(buf2, 1, 0); /* AF ipv4 */
	    push_be_uint(buf2, 2, 1); /* Range size */
	    push_be_uint(buf2, 1, 0); /* Flags */
	    push_be_uint(buf2, 3, 0); /* Reserved */
	    push_data(buf2, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, 4); /* Prefix */
	    break;

	case OSPF_TLV_EXTENDED_PREFIX:
	    push_be_uint(buf2, 2, 1); /* Type */
	    push_be_uint(buf2, 2, 0); /* Length - will be overwritten later */
	    push_be_uint(buf2, 1, 1); /* Route Type: Intra Area */
	    push_be_uint(buf2, 1, attr->key.prefix.ipv4_prefix.len);
	    push_be_uint(buf2, 1, 0); /* AF ipv4 */
	    push_be_uint(buf2, 1, 0); /* Flags */
	    push_data(buf2, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, 4); /* Prefix */
	    break;

	default:
            LOG(ERROR, "No Level 2 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[2]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 2);
    }

    /* open Level 3 */
    if (state & OPEN_LEVEL3) {
	switch(attr->key.attr_cp[3]) {
	case OSPF_SUBTLV_PREFIX_SID:
	    push_be_uint(buf3, 2, 2); /* Type */
	    push_be_uint(buf3, 2, 0); /* Length - will be overwritten later */
	    push_be_uint(buf3, 3, 0); /* Flags, Reserved, MT-ID */
	    push_be_uint(buf3, 1, attr->key.prefix.sid_algo); /* Algorithm */
	    push_be_uint(buf3, 4, attr->key.prefix.sid); /* SID Index */
	    break;

	default:
            LOG(ERROR, "No Level 3 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[3]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 3);
    }

}

void
lspgen_serialize_ospf3_state(lsdb_attr_t *attr, lsdb_packet_t *packet, uint16_t state)
{
    lsdb_ctx_t *ctx;
    lsdb_node_t *node;
    io_buffer_t *buf0, *buf1, *buf2, *buf3;
    uint16_t attr_len, checksum;
    uint32_t router_id;

    node = packet->parent;
    ctx = node->ctx;

    buf0 = &packet->buf[0];
    buf1 = &packet->buf[1];
    buf2 = &packet->buf[2];
    buf3 = &packet->buf[3];

    LOG(PACKET, "  %s\n", lspgen_format_serializer_state(state));

    /* close Level 3 */
    if (state & CLOSE_LEVEL3) {
	switch (packet->prev_attr_cp[3]) {
	case OSPF_SUBTLV_PREFIX_SID:
	    write_be_uint(buf3->data+2, 2, buf3->idx-4); /* Update length */
	    push_pad4(buf3);
	    break;
	default:
	    break;
	}

	lspgen_propagate_buffer_up(packet, 3);
    }

    /* close Level 2 */
    if (state & CLOSE_LEVEL2) {
	switch (packet->prev_attr_cp[2]) {
	case OSPF_TLV_INTRA_AREA_PREFIX:
	    write_be_uint(buf2->data+2, 2, buf2->idx-4); /* Update length */
	    push_pad4(buf2);
	default:
	    break;
	}

	lspgen_propagate_buffer_up(packet, 2);
    }


    /* close Level 1 */
    if (state & CLOSE_LEVEL1) {
	switch (packet->prev_attr_cp[1]) {
	case OSPF_LSA_ROUTER:
	case OSPF_LSA_EXTERNAL:
	case OSPF_LSA_EXTERNAL6:
	case OSPF_LSA_OPAQUE_AREA_RI:
	case OSPF_LSA_OPAQUE_AREA_EP:
	case OSPF_LSA_INTRA_AREA_PREFIX:
	case OSPF_LSA_E_INTRA_AREA_PREFIX: /* fall through */
	default:
	    inc_be_uint(buf0->data+40+16, 4); /* Update #LSAs */
	    write_be_uint(buf1->data+18, 2, buf1->idx); /* Update Packet length */
	    write_be_uint(buf1->data+16, 2, 0); /* reset checksum field */
	    checksum = calculate_fletcher_checksum(buf1->data+2, 14, buf1->idx-2);
	    write_be_uint(buf1->data+16, 2, checksum); /* Update LSA Checksum */
	    if (log_id[DEBUG].enable && validate_fletcher_checksum(buf1->data+2, buf1->idx-2)) {
		    LOG(DEBUG, "Checksum error 0x%04x\n", checksum);
	    }
	    break;
	}

	lspgen_propagate_buffer_up(packet, 1);
    }

    /* close Level 0 */
    if (state & CLOSE_LEVEL0) {
	switch (packet->prev_attr_cp[0]) {
	    case OSPF_MSG_LSUPDATE:
		write_be_uint(buf0->data+40+2, 2, buf0->idx - 40); /* Packet length */
		write_be_uint(buf0->data+4, 2, buf0->idx - 40); /* Payload length */
		write_le_uint(buf0->data+40+12, 2, calculate_ospf3_cksum(buf0->data, buf0->idx)); /* Checksum */
		break;
	default:
	    break;
	}
    }

    /* open Level 0 */
    if (state & OPEN_LEVEL0) {

	switch(attr->key.attr_cp[0]) {
	case OSPF_MSG_LSUPDATE:

	    /* IPv6 header */
	    push_be_uint(buf0, 1, 0x6c); /* Version, Traffic Class MSB */
	    push_be_uint(buf0, 3, 0); /* Flow label  */
	    push_be_uint(buf0, 2, 0); /* Payload length - will be overwritten later */
	    push_be_uint(buf0, 1, 89); /* Next Header */
	    push_be_uint(buf0, 1, 255); /* Hop limit */
            push_data(buf0, (uint8_t *)&ctx->ipv6_node_prefix.address, IPV6_ADDR_LEN); /* Source Address */
	    push_be_uint(buf0, 8, 0xff02000000000000); /* Destination Address */
	    push_be_uint(buf0, 8, 5); /* Destination Address */

	    /* OSPFv3 header */
	    push_be_uint(buf0, 1, 3); /* Version */
	    push_be_uint(buf0, 1, 4); /* Msg: LS-Update */
	    push_be_uint(buf0, 2, 0); /* Packet length - will be overwritten later */

	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf0, 4, router_id); /* Router ID */
	    push_be_uint(buf0, 4, ctx->topology_id.area); /* Area ID */

	    push_be_uint(buf0, 2, 0); /* Checksum - will be overwritten later */

	    push_be_uint(buf0, 1, 0); /* Instance ID */
	    push_be_uint(buf0, 1, 0); /* Reserved */

	    push_be_uint(buf0, 4, 0); /* # LSAs - will be overwritten later */
	    break;
	default:
            LOG(ERROR, "No Level 0 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[0]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 0);
    }

    /* open Level 1 */
    if (state & OPEN_LEVEL1) {

	switch(attr->key.attr_cp[1]) {
	case OSPF_LSA_ROUTER:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 2, 0x2001); /* LS-Type  */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, packet->key.id); /* Link State ID */
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0xffff); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */

	    push_be_uint(buf1, 1, 0x02); /* Flags, E */
	    push_be_uint(buf1, 3, 0x13); /* Options */
	    break;

	case OSPF_LSA_EXTERNAL6:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 2, 0x4005); /* LS-Type  */
	    push_be_uint(buf1, 4, packet->key.id); /* Link State ID */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */

	    push_be_uint(buf1, 1, 0x04); /* E2 */
            push_be_uint(buf1, 3, attr->key.prefix.metric); /* Metric */
	    push_be_uint(buf1, 1, attr->key.prefix.ipv6_prefix.len); /* Prefix Length */
	    push_be_uint(buf1, 1, 0x00); /* Prefix Options */
	    push_be_uint(buf1, 2, 0); /* Referenced LS Type */
	    attr_len = (attr->key.prefix.ipv6_prefix.len+7)/8;
	    push_data(buf1, attr->key.prefix.ipv6_prefix.address, attr_len); /* Prefix */
	    push_pad4(buf1);
	    break;

	case OSPF_LSA_INTRA_AREA_PREFIX:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 2, 0x2009); /* LS-Type  */
	    push_be_uint(buf1, 4, packet->key.id); /* Link State ID */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */

	    push_be_uint(buf1, 2, 0); /* # Prefixes - will be overwritten later */
	    push_be_uint(buf1, 2, 0x2001); /* # Referenced LS Type */

	    push_be_uint(buf1, 4, 0); /* Referenced Link State ID */
	    push_be_uint(buf1, 4, router_id); /* Referenced Advertising Router */
	    break;

	case OSPF_LSA_E_INTRA_AREA_PREFIX:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 2, 0xa029); /* LS-Type  */
	    push_be_uint(buf1, 4, packet->key.id); /* Link State ID */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */

	    push_be_uint(buf1, 2, 0); /* */
	    push_be_uint(buf1, 2, 0x2001); /* # Referenced LS Type */

	    push_be_uint(buf1, 4, 0); /* Referenced Link State ID */
	    push_be_uint(buf1, 4, router_id); /* Referenced Advertising Router */
	    break;


	case OSPF_LSA_OPAQUE_AREA_RI:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 2, 0xa00c); /* LS-Type, flood scope area  */
	    push_be_uint(buf1, 4, 0); /* Link State ID - rfc 4970 section 2.2 says this must be zero */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */
	    break;

	case OSPF_LSA_OPAQUE_AREA_EP:
	    push_be_uint(buf1, 2, lspgen_get_ospf_age(node)); /* LS-age */
	    push_be_uint(buf1, 1, 0); /* Options */
	    push_be_uint(buf1, 1, 10); /* LS-Type  */
	    push_be_uint(buf1, 1, 7); /* Opaque Type: Extended Prefix */
	    push_be_uint(buf1, 3, 0); /* Opaque subtype  */
	    router_id = read_be_uint(node->key.node_id, 4);
	    push_be_uint(buf1, 4, router_id); /* Advertising Router */
	    push_be_uint(buf1, 4, node->sequence); /* Sequence */
	    push_be_uint(buf1, 2, 0); /* Checksum - will be overwritten later */
	    push_be_uint(buf1, 2, 0); /* Length - will be overwritten later */
	    break;

	default:
            LOG(ERROR, "No Level 1 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[1]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 1);
    }

    /*
     * If users wants to generate purges encoding stops at level 1.
     */
    if (ctx->purge) {
	return;
    }

    /* open Level 2 */
    if (state & OPEN_LEVEL2) {
	switch(attr->key.attr_cp[2]) {
	case OSPF_ROUTER_LSA_LINK_PTP:
	    push_be_uint(buf2, 1, 1); /* Type ptp */
	    push_be_uint(buf2, 1, 0); /* #TOS */
	    push_be_uint(buf2, 2, attr->key.link.metric); /* metric */
	    push_be_uint(buf2, 4, read_be_uint(attr->key.link.local_link_id, 4)); /* Interface ID */
	    push_be_uint(buf2, 4, read_be_uint(attr->key.link.remote_link_id, 4)); /* Neighbor Interface ID */
	    push_be_uint(buf2, 4, read_be_uint(attr->key.link.remote_node_id, 4)); /* Neighbor Router  ID */
	    break;

	case OSPF_IA_PREFIX_LSA_PREFIX:
	    push_be_uint(buf2, 1, attr->key.prefix.ipv6_prefix.len); /* Prefix Length */
	    push_be_uint(buf2, 1, 0x00); /* Prefix Options */
            push_be_uint(buf2, 2, attr->key.prefix.metric); /* Metric */
	    attr_len = (attr->key.prefix.ipv6_prefix.len+7)/8;
	    push_data(buf2, attr->key.prefix.ipv6_prefix.address, attr_len); /* Prefix */
	    push_pad4(buf2);

	    inc_be_uint(buf1->data+20, 2); /* Update #prefixes */
	    break;

	case OSPF_TLV_INTRA_AREA_PREFIX:
	    push_be_uint(buf2, 2, 6); /* Type */
	    push_be_uint(buf2, 2, 0); /* Length - will be overwritten later */
	    push_be_uint(buf2, 1, 0);
	    push_be_uint(buf2, 3, attr->key.prefix.metric); /* Metric */
	    push_be_uint(buf2, 1, attr->key.prefix.ipv6_prefix.len); /* Prefix Length */
	    push_be_uint(buf2, 1, 0x00); /* Prefix Options */
	    push_be_uint(buf2, 2, 0);
	    attr_len = (attr->key.prefix.ipv6_prefix.len+7)/8;
	    push_data(buf2, attr->key.prefix.ipv6_prefix.address, attr_len); /* Prefix */
	    push_pad4(buf2);
	    break;

	case OSPF_TLV_HOSTNAME:
	    attr_len = strnlen(attr->key.hostname, sizeof(attr->key.hostname));
	    if (attr_len) {
		push_be_uint(buf2, 2, 7); /* Type */
		push_be_uint(buf2, 2, attr_len); /* Length */
		push_data(buf2, (uint8_t *)attr->key.hostname, attr_len);
		push_pad4(buf2);
	    }
	    break;

	case OSPF_TLV_SID_LABEL_RANGE:
	    if (attr->key.cap.srgb_base && attr->key.cap.srgb_range) {
		push_be_uint(buf2, 2, 9); /* Type */
		push_be_uint(buf2, 2, 0); /* Length - will be overwritten later */
		push_be_uint(buf2, 3, attr->key.cap.srgb_range); /* Range size */
		push_be_uint(buf2, 1, 0); /* Reserved */

		push_be_uint(buf2, 2, 7); /* SID Type Label */
		push_be_uint(buf2, 2, 3); /* SID Type Length */
		push_be_uint(buf2, 3, attr->key.cap.srgb_base);
		push_pad4(buf2);

		write_be_uint(buf2->data+2, 2, buf2->idx-4); /* Update length */
		push_pad4(buf2);
	    }
	    break;

	case OSPF_TLV_EXTENDED_PREFIX_RANGE:
	    push_be_uint(buf2, 2, 2); /* Type */
	    push_be_uint(buf2, 2, 0); /* Length - will be overwritten later */
	    push_be_uint(buf2, 1, attr->key.prefix.ipv4_prefix.len);
	    push_be_uint(buf2, 1, 0); /* AF ipv4 */
	    push_be_uint(buf2, 2, 1); /* Range size */
	    push_be_uint(buf2, 1, 0); /* Flags */
	    push_be_uint(buf2, 3, 0); /* Reserved */
	    push_data(buf2, (uint8_t*)&attr->key.prefix.ipv4_prefix.address, 4); /* Prefix */
	    push_pad4(buf2);
	    break;

	default:
            LOG(ERROR, "No Level 2 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[2]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 2);
    }

    /* open Level 3 */
    if (state & OPEN_LEVEL3) {
	switch(attr->key.attr_cp[3]) {
	case OSPF_SUBTLV_PREFIX_SID:
	    push_be_uint(buf3, 2, 4); /* Type */
	    push_be_uint(buf3, 2, 0); /* Length - will be overwritten later */
	    push_be_uint(buf3, 1, 0); /* Flags */
	    push_be_uint(buf3, 1, attr->key.prefix.sid_algo); /* Algorithm */
	    push_be_uint(buf3, 2, 0); /* Reserved */
	    push_be_uint(buf3, 4, attr->key.prefix.sid); /* SID Index */
	    break;

	default:
            LOG(ERROR, "No Level 3 open packet serializer for attr %s\n",
		val2key(ospf_attr_names, attr->key.attr_cp[3]));
	    return;
	}

	lspgen_propagate_buffer_down(packet, 3);
    }
}

/*
 * Serialize an OSPF attribute into a packet buffer.
 * Pass a custom serialization callback function.
 */
void
lspgen_serialize_ospf_attr(lsdb_attr_t *attr, lsdb_packet_t *packet,
			   void (*serialize_cb)(lsdb_attr_t *, lsdb_packet_t *, uint16_t))
{
    uint16_t state;

    LOG(PACKET, "Serialize attr {0x%02x, 0x%02x, 0x%02x, 0x%02x}, last attr {0x%02x, 0x%02x, 0x%02x, 0x%02x}\n",
	attr->key.attr_cp[0],
	attr->key.attr_cp[1],
	attr->key.attr_cp[2],
	attr->key.attr_cp[3],
	packet->prev_attr_cp[0],
	packet->prev_attr_cp[1],
	packet->prev_attr_cp[2],
	packet->prev_attr_cp[3]);

    /*
     * Fresh message ?
     */
    state = 0;
    if (attr->key.attr_cp[0] && packet->prev_attr_cp[0] == 0) {
	state |= OPEN_LEVEL0;
	if (attr->key.attr_cp[1] && packet->prev_attr_cp[1] == 0) {
	    state |= OPEN_LEVEL1;
	    if (attr->key.attr_cp[2] && packet->prev_attr_cp[2] == 0) {
		state |= OPEN_LEVEL2;
		if (attr->key.attr_cp[3] && packet->prev_attr_cp[3] == 0) {
		    state |= OPEN_LEVEL3;
		}
	    }
	}
	(*serialize_cb)(attr, packet, state);
	return;
    }

    /*
     * Different L0 message ?
     */
    if (packet->prev_attr_cp[0] != attr->key.attr_cp[0]) {
	state |= CLOSE_LEVEL0;
	if (attr->key.attr_cp[0]) {
	    state |= OPEN_LEVEL0;
	}
	if (packet->prev_attr_cp[3]) {
	    state |= CLOSE_LEVEL3;
	}
	if (attr->key.attr_cp[3]) {
	    state |= OPEN_LEVEL3;
	}
	if (packet->prev_attr_cp[2]) {
	    state |= CLOSE_LEVEL2;
	}
	if (attr->key.attr_cp[2]) {
	    state |= OPEN_LEVEL2;
	}
	if (packet->prev_attr_cp[1]) {
	    state |= CLOSE_LEVEL1;
	}
	if (attr->key.attr_cp[1]) {
	    state |= OPEN_LEVEL1;
	}
	(*serialize_cb)(attr, packet, state);
	return;
    }

    /*
     * Different L1 message ?
     */
    if (packet->prev_attr_cp[1] != attr->key.attr_cp[1]) {
	state |= CLOSE_LEVEL1;
	if (attr->key.attr_cp[1]) {
	    state |= OPEN_LEVEL1;
	}
	if (packet->prev_attr_cp[2]) {
	    state |= CLOSE_LEVEL2;
	}
	if (attr->key.attr_cp[2]) {
	    state |= OPEN_LEVEL2;
	}
	if (packet->prev_attr_cp[3]) {
	    state |= CLOSE_LEVEL3;
	}
	if (attr->key.attr_cp[3]) {
	    state |= OPEN_LEVEL3;
	}
	(*serialize_cb)(attr, packet, state);
	return;
    }

    /*
     * Different L2 message ?
     */
    if (packet->prev_attr_cp[2] != attr->key.attr_cp[2]) {
	state |= CLOSE_LEVEL2;
	if (attr->key.attr_cp[2]) {
	    state |= OPEN_LEVEL2;
	}
	if (packet->prev_attr_cp[3]) {
	    state |= CLOSE_LEVEL3;
	}
	if (attr->key.attr_cp[3]) {
	    state |= OPEN_LEVEL3;
	}
	(*serialize_cb)(attr, packet, state);
	return;
    }

    /*
     * Different L3 message ?
     */
    if (packet->prev_attr_cp[3] != attr->key.attr_cp[3]) {
	state |= CLOSE_LEVEL3;
	if (attr->key.attr_cp[3]) {
	    state |= OPEN_LEVEL3;
	}
	(*serialize_cb)(attr, packet, state);
	return;
    }

    /*
     * Same message codepoints ?
     */
    if (memcmp(packet->prev_attr_cp, attr->key.attr_cp, MAX_MSG_LEVEL) == 0) {

	/*
	 * Figure out max level.
	 */
	if (attr->key.attr_cp[3]) {
	    state |= OPEN_LEVEL3;
	} else if (attr->key.attr_cp[2]) {
	    state |= OPEN_LEVEL2;
	} else if (attr->key.attr_cp[1]) {
	    state |= OPEN_LEVEL1;
	} else if (attr->key.attr_cp[0]) {
	    state |= OPEN_LEVEL0;
	}

	/* Enforce building fresh messages ?*/
	if (attr->key.start_tlv) {

	    /* Clone close state from open state */
	    state |= state << 8;
	}

	(*serialize_cb)(attr, packet, state);
	return;
    }
}

/*
 * Serialize an attribute into a buffer.
 *
 * This is used in two places.
 *  1) When an attribute gets added for size measurement.
 *  2) When the actual packet gets built.
 */
void
lspgen_serialize_attr(lsdb_ctx_t *ctx, lsdb_attr_t *attr, lsdb_packet_t *packet)
{
    switch (ctx->protocol_id) {
    case PROTO_ISIS:
	lspgen_serialize_isis_attr(attr, packet);
	break;
    case PROTO_OSPF2:
	lspgen_serialize_ospf_attr(attr, packet, lspgen_serialize_ospf2_state);
	break;
    case PROTO_OSPF3:
	lspgen_serialize_ospf_attr(attr, packet, lspgen_serialize_ospf3_state);
	break;
    default:
	LOG_NOARG(ERROR, "Unknown protocol\n");
    }

    /*
     * Update array of last codepoints, such that the serializer can correctly
     * call into the open/close functions across all the <MAX_MSG_LEVEL> levels.
     */
    memcpy(&packet->prev_attr_cp, &attr->key.attr_cp, sizeof(packet->prev_attr_cp));
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
 * Reset all packet buffers.
 */
void
lspgen_reset_packet_buffer (struct lsdb_packet_ *packet)
{
    struct io_buffer_ *buf;
    uint idx;

    buf = &packet->buf[0];

    buf->data = packet->data;
    buf->start_idx = 0;
    buf->idx = 0;
    buf->size = sizeof(packet->data);
    for (idx = 1; idx < MAX_MSG_LEVEL; idx++) {
	memcpy(&packet->buf[idx], buf, sizeof(struct io_buffer_));
    }

    /*
     * Reset prev attribute codepoint cache.
     */
    memset(&packet->prev_attr_cp, 0, sizeof(packet->prev_attr_cp));
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
	 * Reset buffers.
	 */
	lspgen_reset_packet_buffer(packet);

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
 * Should we start a new packet ?
 */
bool
lspgen_should_start_new_packet (lsdb_ctx_t *ctx, struct lsdb_packet_ *packet, struct lsdb_attr_ *attr)
{
    uint32_t min_len;

    if (!packet) {
	return false;
    }

    min_len = lspgen_calculate_auth_len(ctx);
    min_len += attr->size;

    /*
     * Protocols have different max PDU sizes.
     */
    switch (ctx->protocol_id) {
    case PROTO_ISIS:
	min_len =+ TLV_OVERHEAD;
        if (packet->buf[0].idx > (1465-min_len)) {
	    return true;
	}
	break;

    case PROTO_OSPF2:
	if (packet->buf[0].idx > (sizeof(packet->data) -60 -min_len)) {
	    return true;
	}
	break;

    case PROTO_OSPF3:
	if (packet->buf[0].idx > (sizeof(packet->data) -60 -min_len)) {
	    return true;
	}

	/*
	 * Do not build router-LSAs larger than IPv6 min MTU.
	 */
	if (attr->key.attr_cp[1] == OSPF_LSA_ROUTER &&
	    packet->buf[2].idx > 1170) {
	    LOG(PACKET, "Max OSPF3 Router LSA size of %u reached\n", packet->buf[2].idx);
	    return true;
	}

	/*
	 * Do not build Intra-Area-Prefix LSAs larger than IPv6 min MTU.
	 */
	if (attr->key.attr_cp[1] == OSPF_LSA_INTRA_AREA_PREFIX &&
	    packet->buf[2].idx > 1170) {
	    LOG(PACKET, "Max OSPF3 Intra-Area Prefix LSA size of %u reached\n", packet->buf[2].idx);
	    return true;
	}
	break;
    default:
	LOG_NOARG(ERROR, "Unknown protocol\n");
	break;
    }

    return false;
}

/*
 * Walk the graph of the LSDB and serialize IS-IS packets.
 */
void
lspgen_gen_isis_packet_node(lsdb_node_t *node)
{
    lsdb_ctx_t *ctx;
    struct lsdb_packet_ *packet;
    struct lsdb_attr_ *attr;
    dict_itor *itor;
    uint32_t id, last_attr, tlv_start_idx;

    ctx = node->ctx;

    packet = NULL;
    id = 0;
    last_attr = 0;
    tlv_start_idx = 0;

    /*
     * Flush old serialized packets.
     */
    dict_clear(node->packet_dict, lsdb_free_packet);

    if (!node->attr_dict || ctx->purge) {

        /*
         * Purge if no attributes or explicit purge.
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
        if (lspgen_should_start_new_packet(ctx, packet, attr)) {

            /*
            * No space left. Finalize this packet.
            */
            lspgen_finalize_packet(ctx, node, packet);
            packet = NULL;

            id++;
            if (id > MAX_ISIS_FRAGMENT-1) {
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
            tlv_start_idx = packet->buf[0].idx;
        }

        /*
         * Encode node attributes.
         */

        /*
         * Start a fresh TLV ?
         */
        if ((last_attr != attr->key.attr_type) ||
            (lspgen_calculate_tlv_space(&packet->buf[0], tlv_start_idx) < attr->size) ||
	    attr->key.start_tlv) {
            tlv_start_idx = packet->buf[0].idx;
            push_be_uint(&packet->buf[0], 1, attr->key.attr_type); /* Type */
            push_be_uint(&packet->buf[0], 1, 0); /* Length */
        }

        lspgen_serialize_attr(ctx, attr, packet);
        lspgen_update_tlv_length(&packet->buf[0], tlv_start_idx);

        last_attr = attr->key.attr_type;

    } while (dict_itor_next(itor));

    lspgen_finalize_packet(ctx, node, packet);
    dict_itor_free(itor);
}

/*
 * Walk the graph of the LSDB and serialize OSPF2 and OSPF3 packets.
 */
void
lspgen_gen_ospf_packet_node(lsdb_node_t *node)
{
    lsdb_ctx_t *ctx;
    struct lsdb_packet_ *packet;
    struct lsdb_attr_ *attr;
    dict_itor *itor;
    uint32_t id;

    ctx = node->ctx;

    packet = NULL;
    id = 0;

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
        if (lspgen_should_start_new_packet(ctx, packet, attr)) {

            /*
	     * No space left. Finalize this packet.
	     */
            lspgen_finalize_packet(ctx, node, packet);
            packet = NULL;

            id++;
            if (id > MAX_OSPF_PACKET-1) {
                dict_itor_free(itor);
                LOG(ERROR, "Exhausted packets for node %s\n", lsdb_format_node(node));
                return;
            }
        }

        /*
         * Need a fresh packet ?
         */
        if (!packet) {
            packet = lspgen_add_packet(ctx, node, id);
        }

        /*
         * Encode node attributes.
         */
        lspgen_serialize_attr(ctx, attr, packet);

    } while (dict_itor_next(itor));

    lspgen_finalize_packet(ctx, node, packet);
    dict_itor_free(itor);
}

void
lspgen_gen_packet_node(lsdb_node_t *node)
{
    lsdb_ctx_t *ctx;

    ctx = node->ctx;
    switch (ctx->protocol_id) {
    case PROTO_ISIS:
	lspgen_gen_isis_packet_node(node);
	break;
    case PROTO_OSPF2: /* fall through */
    case PROTO_OSPF3:
	lspgen_gen_ospf_packet_node(node);
	break;
    default:
	LOG_NOARG(ERROR, "Unknown protocol\n");
    }
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
     * Do not smear if this is a one-off LSDB drain.
     */
    if (!ctx->quit_loop) {

	/*
	 * Distribute expiration of refresh timer over time.
	 */
	timer_smear_bucket(&ctx->timer_root, lspgen_refresh_interval(ctx), 0);
    }
}
