/*
 * BNG Blaster (BBL) - PCAP
 * Write packets to a file in pcapng format.
 *
 * Hannes Gredler, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
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

/*
 * APIs
 */
void pcapng_init(bbl_ctx_s *);
void pcapng_free(bbl_ctx_s *);
void pcapng_push_section_header(bbl_ctx_s *);
void pcapng_push_interface_header(bbl_ctx_s *, uint, const char *);
void pcapng_push_packet_header(bbl_ctx_s *, struct timespec *, u_char *, uint, uint, uint);
void pcapng_fflush(bbl_ctx_s *);

#endif
