/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_bio_adapter.h - stream/BIO adapter for use in the IETF QUIC
 * crypto stream.
 */

#ifndef LSQUIC_BIO_ADAPTER_H
#define LSQUIC_BIO_ADAPTER_H 1

struct bio_method_st;
struct lsquic_cid;

extern const struct bio_method_st *const lsquic_bio_adapter;

struct stream_wrapper
{
    void       *sw_ctx;
    ssize_t   (*sw_read)(void *sw_ctx, void *buf, size_t);
    ssize_t   (*sw_write)(void *sw_ctx, const void *buf, size_t);
    int       (*sw_flush)(void *sw_ctx);
    const struct lsquic_cid *sw_cid;     /* used for logging */
};

#endif
