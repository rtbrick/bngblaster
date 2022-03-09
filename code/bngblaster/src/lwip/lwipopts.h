/*
 * BNG Blaster (BBL) - LwIP Configuration
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#define LWIP_DBG_MIN_LEVEL  0
#define LWIP_COMPAT_SOCKETS 1

#define TAPIF_DEBUG      LWIP_DBG_OFF
#define TUNIF_DEBUG      LWIP_DBG_OFF
#define UNIXIF_DEBUG     LWIP_DBG_OFF
#define DELIF_DEBUG      LWIP_DBG_OFF
#define SIO_FIFO_DEBUG   LWIP_DBG_OFF
#define TCPDUMP_DEBUG    LWIP_DBG_OFF

#define PPP_DEBUG        LWIP_DBG_OFF
#define MEM_DEBUG        LWIP_DBG_OFF
#define MEMP_DEBUG       LWIP_DBG_OFF
#define PBUF_DEBUG       LWIP_DBG_OFF
#define API_LIB_DEBUG    LWIP_DBG_OFF
#define API_MSG_DEBUG    LWIP_DBG_OFF
#define TCPIP_DEBUG      LWIP_DBG_OFF
#define NETIF_DEBUG      LWIP_DBG_OFF
#define SOCKETS_DEBUG    LWIP_DBG_OFF
#define DEMO_DEBUG       LWIP_DBG_OFF
#define IP_DEBUG         LWIP_DBG_OFF
#define IP_REASS_DEBUG   LWIP_DBG_OFF
#define RAW_DEBUG        LWIP_DBG_OFF
#define ICMP_DEBUG       LWIP_DBG_OFF
#define UDP_DEBUG        LWIP_DBG_OFF
#define TCP_DEBUG        LWIP_DBG_OFF
#define TCP_INPUT_DEBUG  LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG LWIP_DBG_OFF
#define TCP_RTO_DEBUG    LWIP_DBG_OFF
#define TCP_CWND_DEBUG   LWIP_DBG_OFF
#define TCP_WND_DEBUG    LWIP_DBG_OFF
#define TCP_FR_DEBUG     LWIP_DBG_OFF
#define TCP_QLEN_DEBUG   LWIP_DBG_OFF
#define TCP_RST_DEBUG    LWIP_DBG_OFF

extern unsigned char debug_flags;
#define LWIP_DBG_TYPES_ON debug_flags

#define NO_SYS                     1
#define LWIP_SOCKET                (NO_SYS==0)
#define LWIP_NETCONN               (NO_SYS==0)

#define LWIP_ETHERNET              1
#define LWIP_IPV4                  1
#define LWIP_IPV6                  1

#define LWIP_IPV6_REASS            0
#define LWIP_IPV6_AUTOCONFIG       0

/* ---------- Memory options ---------- */
/* MEM_ALIGNMENT: should be set to the alignment of the CPU for which
   lwIP is compiled. 4 byte alignment -> define MEM_ALIGNMENT to 4, 2
   byte alignment -> define MEM_ALIGNMENT to 2. */
/* MSVC port: intel processors don't need 4-byte alignment,
   but are faster that way! */
#define MEM_ALIGNMENT            4

/* MEM_SIZE: the size of the heap memory. If the application will send
a lot of data that needs to be copied, this should be set high. */
#define MEM_SIZE                 10240 

/* MEMP_NUM_PBUF: the number of memp struct pbufs. If the application
   sends a lot of data out of ROM (or other static memory), this
   should be set high. */
#define MEMP_NUM_PBUF            64
/* MEMP_NUM_RAW_PCB: the number of UDP protocol control blocks. One
   per active RAW "connection". */
#define MEMP_NUM_RAW_PCB         3
/* MEMP_NUM_UDP_PCB: the number of UDP protocol control blocks. One
   per active UDP "connection". */
#define MEMP_NUM_UDP_PCB         4
/* MEMP_NUM_TCP_PCB: the number of simultaneously active TCP
   connections. */
#define MEMP_NUM_TCP_PCB         32
/* MEMP_NUM_TCP_PCB_LISTEN: the number of listening TCP
   connections. */
#define MEMP_NUM_TCP_PCB_LISTEN  32
/* MEMP_NUM_TCP_SEG: the number of simultaneously queued TCP
   segments. */
#define MEMP_NUM_TCP_SEG         32
/* MEMP_NUM_SYS_TIMEOUT: the number of simultaneously active
   timeouts. */
#define MEMP_NUM_SYS_TIMEOUT     65

/* The following four are used only with the sequential API and can be
   set to 0 if the application only will use the raw API. */
/* MEMP_NUM_NETBUF: the number of struct netbufs. */
#define MEMP_NUM_NETBUF          2
/* MEMP_NUM_NETCONN: the number of struct netconns. */
#define MEMP_NUM_NETCONN         10
/* MEMP_NUM_TCPIP_MSG_*: the number of struct tcpip_msg, which is used
   for sequential API communication and incoming packets. Used in
   src/api/tcpip.c. */
#define MEMP_NUM_TCPIP_MSG_API   16
#define MEMP_NUM_TCPIP_MSG_INPKT 16

/* ---------- Pbuf options ---------- */
/* PBUF_POOL_SIZE: the number of buffers in the pbuf pool. */
#define PBUF_POOL_SIZE          120

/* PBUF_POOL_BUFSIZE: the size of each pbuf in the pbuf pool. */
#define PBUF_POOL_BUFSIZE       256

/* PBUF_LINK_HLEN: the number of bytes that should be allocated for a
   link level header. */
#define PBUF_LINK_HLEN          16 

/** SYS_LIGHTWEIGHT_PROT
 * define SYS_LIGHTWEIGHT_PROT in lwipopts.h if you want inter-task protection
 * for certain critical regions during buffer allocation, deallocation and memory
 * allocation and deallocation.
 */
#define SYS_LIGHTWEIGHT_PROT           1

/* ---------- TCP options ---------- */
#define LWIP_TCP                1
#define TCP_TTL                 255

/* Controls if TCP should queue segments that arrive out of
   order. Define to 0 if your device is low on memory. */
#define TCP_QUEUE_OOSEQ         1

/* TCP Maximum segment size. */
#define TCP_MSS                 1024

/* TCP sender buffer space (bytes). */
#define TCP_SND_BUF             2048

/* TCP sender buffer space (pbufs). This must be at least = 2 *
   TCP_SND_BUF/TCP_MSS for things to work. */
#define TCP_SND_QUEUELEN        (4 * TCP_SND_BUF/TCP_MSS)

/* TCP writable space (bytes). This must be less than or equal
   to TCP_SND_BUF. It is the amount of space which must be
   available in the tcp snd_buf for select to return writable */
#define TCP_SNDLOWAT		    (TCP_SND_BUF/2)

/* TCP receive window. */
#define TCP_WND                 8096

/* Maximum number of retransmissions of data segments. */
#define TCP_MAXRTX              12

/* Maximum number of retransmissions of SYN segments. */
#define TCP_SYNMAXRTX           12

#define TCP_LISTEN_BACKLOG      1
#define LWIP_CALLBACK_API       1

/* ---------- ARP options ---------- */
#define LWIP_ARP                1

/* ---------- IP options ---------- */
/* Define IP_FORWARD to 1 if you wish to have the ability to forward
   IP packets across network interfaces. If you are going to run lwIP
   on a device with only one network interface, define this to 0. */
#define IP_FORWARD              0

/* IP reassembly and segmentation.These are orthogonal even
 * if they both deal with IP fragments */
#define IP_REASSEMBLY           0
#define IP_FRAG                 0

/* ---------- ICMP options ---------- */
#define ICMP_TTL                255

/* ---------- DHCP options ---------- */
/* Define LWIP_DHCP to 1 if you want DHCP configuration of
   interfaces. */
#define LWIP_DHCP               0

/* ---------- AUTOIP options ------- */
#define LWIP_AUTOIP             0

/* ---------- RAW options ---------- */
#define LWIP_RAW                1
#define RAW_TTL                 255

/* ---------- Statistics options ---------- */
/* individual STATS options can be turned off by defining them to 0 
 * (e.g #define TCP_STATS 0). All of them are turned off if LWIP_STATS
 * is 0
 * */
#define LWIP_STATS	1

#endif /* __LWIPOPTS_H__ */
