/*
 * BNG Blaster Protocols Decode Fuzzing
 *
 * Author(s): Christian Giese
 *
 * Copyright (C) 2016 - 2020, RtBrick, Inc.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <bbl.h>
#include <bbl_protocols.h>

#define SCRATCHPAD_LEN     1514
#define BUFFER_SIZE        64000

static uint8_t scratchpad[SCRATCHPAD_LEN];
static uint8_t buffer[BUFFER_SIZE];

int main(int argc, char *argv[]) {

    bbl_ethernet_header_t *eth;
    protocol_error_t decode_result;
    uint8_t *sp = scratchpad;
    uint8_t *buf = buffer;
    uint8_t *input = NULL;
    uint16_t len;
    int fd;

    assert(argc == 2);
    fd = open(argv[1], O_RDONLY);
    assert(fd >= 0);

    /* find file size */
    len = lseek(fd, 0, SEEK_END);
    assert(len);

    /* jump back to beginning */
    lseek(fd, 0, SEEK_SET);
    input = mmap(
            NULL, /* pointer */
            len, /* length */
            PROT_READ, /* read only */
            MAP_PRIVATE, /* flags */
            fd, /* file descriptor */
            0); /* offset */

    if(len <= BUFFER_SIZE) {
        /* copy input to buffer */
        buf += BUFFER_SIZE - len;
        memcpy(buf, input, len);
        /* call test function */
        decode_result = decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            printf("OK\n");
        } else {
            printf("FAILED\n");
        }
    }
    return 0;
}
