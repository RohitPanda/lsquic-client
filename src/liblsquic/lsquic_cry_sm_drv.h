/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cry_sm_dvr.h - Crypto Stream Driver
 */

#ifndef LSQUIC_CRY_SM_DVR_H
#define LSQUIC_CRY_SM_DVR_H 1

struct lsquic_conn;
struct lsquic_stream;

struct crypto_stream_driver
{
    enum {
        CSD_DISCARD = 1 << 0,
    }                        csd_flags;
    struct lsquic_conn      *csd_conn;
    struct lsquic_stream    *csd_stream;
    struct stream_wrapper    csd_stream_wrapper;
};

extern const struct lsquic_stream_if lsquic_cry_sm_if;

#endif
