/*
 * BNG Blaster (BBL) - Netmap
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_pcap.h"
#include "bbl_rx.h"
#include "bbl_tx.h"

#ifdef BNGBLASTER_AF_XDP

#include <bpf/bpf.h>
#include <bpf/xsk.h>

void
bbl_io_af_xdp_rx_job (timer_s *timer)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;

    UNUSED(ctx);
}

void
bbl_io_af_xdp_tx_job (timer_s *timer)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;

    UNUSED(ctx);
}

/**
 * bbl_io_af_xdp_send
 *
 * Send single packet trough given interface.
 *
 * @param interface interface.
 * @param packet packet to be send
 * @param packet_len packet length
 */
bool
bbl_io_af_xdp_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len) {
    UNUSED(interface);
    UNUSED(packet);
    UNUSED(packet_len);
    return true;
}

/**
 * bbl_io_af_xdp_add_interface
 *
 * @param ctx global context
 * @param interface interface.
 */
bool
bbl_io_af_xdp_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface) {
    char timer_name[128];
	struct xsk_umem_info *umem;

	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	uint32_t prog_id = 0;
	int i;
	int ret;

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
        LOG(ERROR, "Can't create umem \"%s\"\n", strerror(errno));
        return false;
	}


	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = 0;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
				 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);

	if (ret)
		goto error_exit;


    /*
     * Add an periodic timer for polling I/O.
     */
    snprintf(timer_name, sizeof(timer_name), "%s TX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->tx_job, timer_name, 0, ctx->config.tx_interval, interface, &bbl_io_af_xdp_tx_job);
    snprintf(timer_name, sizeof(timer_name), "%s RX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->rx_job, timer_name, 0, ctx->config.rx_interval, interface, &bbl_io_af_xdp_rx_job);

    return true;
}

#endif
