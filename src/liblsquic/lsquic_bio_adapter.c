/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <errno.h>
#include <string.h>

#include <openssl/bio.h> 

#include "lsquic.h"
#include "lsquic_bio_adapter.h"

#define LSQUIC_LOGGER_MODULE LSQLM_BIO_ADAPTER
#define LSQUIC_LOG_CONN_ID stream->sw_cid
#include "lsquic_logger.h"


static int
stream_adapter_bio_write (BIO *bio, const char *buf, int len)
{
    struct stream_wrapper *const stream = BIO_get_data(bio);
    ssize_t nw;

    nw = stream->sw_write(stream->sw_ctx, buf, len);
    if (nw >= 0)
        LSQ_DEBUG("wrote %zd bytes out of %d", nw, len);
    else if (errno == EWOULDBLOCK)
    {
        LSQ_DEBUG("cannot write %d bytes -- retry", len);
        BIO_set_retry_write(bio);
    }
    else
        LSQ_DEBUG("cannot write %d bytes: %s", len, strerror(errno));
    return nw;
}


static int
stream_adapter_bio_read (BIO *bio, char *buf, int len)
{
    struct stream_wrapper *const stream = BIO_get_data(bio);
    ssize_t nr;

    nr = stream->sw_read(stream->sw_ctx, buf, len);
    if (nr >= 0)
        LSQ_DEBUG("read %zd bytes out of %d", nr, len);
    else if (errno == EWOULDBLOCK)
    {
        LSQ_DEBUG("cannot read %d bytes -- retry", len);
        BIO_set_retry_read(bio);
    }
    else
        LSQ_DEBUG("cannot read %d bytes: %s", len, strerror(errno));
    return nr;
}


static long
stream_adapter_bio_ctrl (BIO *bio, int cmd, long arg, void *parg)
{
    struct stream_wrapper *stream;

    stream = BIO_get_data(bio);
    switch (cmd)
    {
    case BIO_CTRL_FLUSH:
        if (0 == stream->sw_flush(stream->sw_ctx))
        {
            LSQ_DEBUG("successfully flushed");
            return 1;
        }
        else
        {
            LSQ_WARN("could not flush stream: %d", errno);
            return 0;
        }
        break;
    default:
        LSQ_DEBUG("unsupported BIO ctrl command %d; return 0", cmd);
        return 0;
    }
}


static const struct bio_method_st bio_adapter =
{
    .type   = 0,    /* XXX? */
    .name   = "BIO/Stream Adapter",
    .bwrite = stream_adapter_bio_write,
    .bread  = stream_adapter_bio_read,
    .ctrl   = stream_adapter_bio_ctrl,
};


const struct bio_method_st *const lsquic_bio_adapter = &bio_adapter;
