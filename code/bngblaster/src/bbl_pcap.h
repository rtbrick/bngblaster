/*
 * BNG Blaster (BBL) - PCAP
 * Write packets to a file in pcapng format.
 *
 * Hannes Gredler, October 2020
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_PCAP_H__
#define __BBL_PCAP_H__

#define PCAPNG_WRITEBUFSIZE 65536
#define PCAPNG_PERMS 0644

#define PCAPNG_SHB 0x0a0d0d0a
#define PCAPNG_SHB_USERAPPL_OPTION 4
#define PCAPNG_SHB_USERAPPL "rtbrick-bngblaster"

#define PCAPNG_IDB 0x00000001
#define PCAPNG_IDB_IFNAME_OPTION 2

#define PCAPNG_EPB 0x00000006
#define PCAPNG_EPB_FLAGS_OPTION 2
#define PCAPNG_EPB_FLAGS_INBOUND  0x1
#define PCAPNG_EPB_FLAGS_OUTBOUND 0x2

/* Ethernet (10Mb, 100Mb, 1000Mb, and up);
 * the 10MB in the DLT_ name is historical. */
#define DLT_EN10MB        1 /* Ethernet (10Mb) */
#define DLT_NULL          0 /* RAW IP */

void
pcapng_open();

void
pcapng_init();

void
pcapng_fflush();

void
pcapng_free();

void
pcapng_push_packet_header(struct timespec *ts, uint8_t *data, uint32_t packet_length,
                          uint32_t ifindex, uint32_t direction);

#endif
