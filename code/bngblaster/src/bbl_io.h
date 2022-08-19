/*
 * BNG Blaster (BBL) - IO
 *
 * Christian Giese, October 2020
 *
 * RAW socket IO with optional PACKET_MMAP ring.
 *
 * PACKET_MMAP provides a size configurable circular buffer mapped in user space
 * that can be used to either send or receive packets. This way reading packets
 * just needs to wait for them, most of the time there is no need to issue a single
 * system call. Concerning transmission, multiple packets can be sent through one
 * system call to get the highest bandwidth. By using a shared buffer between the
 * kernel and the user also has the benefit of minimizing packet copies.
 *
 * https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_IO_H__
#define __BBL_IO_H__

bool
bbl_io_send(bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len);

bool
bbl_io_add_interface(bbl_interface_s *interface);

#endif
