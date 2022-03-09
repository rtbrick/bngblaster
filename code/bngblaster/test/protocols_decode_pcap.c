/*
 * BNG Blaster (BBL) - Decode PCAP Test
 *
 * This simple application is build to test
 * and messure the protocols decode functionality
 * of the BNG Blaster by decoding a given PCAP
 * file and printing some statistics about.
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <bbl_def.h>
#include <bbl_protocols.h>

#include "ethernet_packets.h"

typedef struct input_packets_ {
    uint8_t *packet;
    uint16_t len;
    void *next;
} input_packets_t;

input_packets_t *g_input_packets_head;
input_packets_t *g_input_packets_next;

uint8_t *g_scratchpad;
uint32_t g_packets;
uint32_t g_decode_errors;
uint32_t g_decode_unknown;

void
packet_handler (u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    (void)(user_data);
    if(g_input_packets_next->len) {
        g_input_packets_next->next = calloc(1, sizeof(input_packets_t));
        g_input_packets_next = g_input_packets_next->next;
    }
    g_input_packets_next->packet = malloc(pkthdr->len);
    g_input_packets_next->len = pkthdr->len;
    memcpy(g_input_packets_next->packet, (uint8_t*)packet, pkthdr->len);
}

int
main(int argc, char **argv) {

    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    double result;
    double min = 0;
    double max = 0;
    double avg = 0;
    double sum = 0;

    struct timespec tstart={0,0}, tend={0,0};
    protocol_error_t decode_result;
    bbl_ethernet_header_t *eth;

    g_input_packets_head = calloc(1, sizeof(input_packets_t));
    g_input_packets_next = g_input_packets_head;
    g_scratchpad = calloc(1, SCRATCHPAD_LEN);
    g_packets = 0;
    g_decode_errors = 0;
    g_decode_unknown = 0;

    if(argc != 2) {
        printf("Usage: %s filename\n", argv[0]);
        exit(1);
    }

    fp = pcap_open_offline(argv[1], errbuf);
    if (fp == NULL) {
        fprintf(stderr, "\nFailed to open PCAP: %s\n", errbuf);
        exit(1);
    }

    /* Load PCAP to memory... */
    if (pcap_loop(fp, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "\nReading PCAP failed: %s\n", pcap_geterr(fp));
        exit(1);
    }

    for(i = 0; i < 100; i++) {
        clock_gettime(CLOCK_MONOTONIC, &tstart);
        g_input_packets_next = g_input_packets_head;
        while(g_input_packets_next) {
            decode_result = decode_ethernet((uint8_t*)g_input_packets_next->packet, g_input_packets_next->len, g_scratchpad, SCRATCHPAD_LEN, &eth);
            if(decode_result != PROTOCOL_SUCCESS) {
                if(decode_result == UNKNOWN_PROTOCOL) {
                    g_decode_unknown++;
                } else {
                    g_decode_errors++;
                }
            }
            g_packets++;
            g_input_packets_next = g_input_packets_next->next;
        }
        clock_gettime(CLOCK_MONOTONIC, &tend);
        result = ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) -
                 ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);

        sum += result;
        if(result > max) max = result;
        if(min) {
            if(result < min) min = result;
        } else {
            min = result;
        }
    }
    avg = sum / 100;
    printf("Packets Decoded: %d Errors: %d Unkown: %d\n", g_packets, g_decode_errors, g_decode_unknown);
    printf("Time Min: %.9f seconds Avg: %.9f seconds Max %.9f seconds\n", min, avg, max);
}