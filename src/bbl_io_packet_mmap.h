/*
 * BNG Blaster (BBL) - PACKET_MMAP
 *
 * Christian Giese, October 2021
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
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_IO_PACKET_MMAP_H__
#define __BBL_IO_PACKET_MMAP_H__

typedef struct bbl_io_packet_mmap_ctx_
{
    int fd_tx;
    int fd_rx;
    
    struct tpacket_req req_tx;
    struct tpacket_req req_rx;
    struct sockaddr_ll addr;
    uint8_t *buf;    
    uint8_t *ring_tx; /* ringbuffer */
    uint8_t *ring_rx; /* ringbuffer */
    uint16_t cursor_tx; /* slot # inside the ringbuffer */
    uint16_t cursor_rx; /* slot # inside the ringbuffer */

    bool pollout;
} bbl_io_packet_mmap_ctx;

bool
bbl_io_packet_mmap_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len);

bool
bbl_io_packet_mmap_raw_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len);

bool
bbl_io_packet_mmap_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface, int slots, bbl_io_mode_t io_mode);

#endif