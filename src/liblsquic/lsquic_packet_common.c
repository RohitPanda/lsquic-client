/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_common.c -- some common packet-related routines
 */

#include <stdio.h>

#include "lsquic_types.h"
#include "lsquic_logger.h"
#include "lsquic_packet_common.h"


const char *
lsquic_frame_types_to_str (char *buf, size_t bufsz,
                                           enum quic_ft_bit frame_types)
{
    char *p;
    int i, w;
    size_t sz;

    if (bufsz > 0)
        buf[0] = '\0';

    p = buf;
    for (i = 0; i < N_QUIC_FRAMES; ++i)
    {
        if (frame_types & (1 << i))
        {
            sz = bufsz - (p - buf);
            w = snprintf(p, sz, "%.*s%s", p > buf, " ",
                            frame_type_2_str[i] + sizeof("QUIC_FRAME_") - 1);
            if (w > (int) sz)
            {
                LSQ_WARN("not enough room for all frame types");
                break;
            }
            p += w;
        }
        frame_types &= ~(1 << i);
    }

    return buf;
}


const char *const lsquic_hety2str[] =
{
    [HETY_NOT_SET]      = "Short",
    [HETY_VERNEG]       = "Version Negotiation",
    [HETY_INITIAL]      = "Initial",
    [HETY_RETRY]        = "Retry",
    [HETY_HANDSHAKE]    = "Handshake",
    [HETY_0RTT]         = "0-RTT",
};
