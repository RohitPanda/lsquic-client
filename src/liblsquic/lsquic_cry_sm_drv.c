/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * Crypto stream driver
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_bio_adapter.h"
#include "lsquic_cry_sm_drv.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HSK_ADAPTER
#define LSQUIC_LOG_CONN_ID &driver->csd_conn->cn_cid
#include "lsquic_logger.h"


static lsquic_stream_ctx_t *
chsk_ietf_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct crypto_stream_driver *const driver = stream_if_ctx;

    if (
        0 != driver->csd_conn->cn_esf.i->esfi_init_client(
                                            driver->csd_conn->cn_enc_session))
    {
        LSQ_DEBUG("enc session could not initialized");
        goto end;
    }

    assert(driver->csd_stream == stream);
    driver->csd_stream_wrapper = (struct stream_wrapper) {
        .sw_ctx = stream,
        .sw_read = (ssize_t (*)(void *, void *, size_t)) lsquic_stream_read,
        .sw_write = (ssize_t (*)(void *, const void *, size_t))
                                                        lsquic_stream_write,
        .sw_flush = (int (*)(void *)) lsquic_stream_flush,
        .sw_cid = LSQUIC_LOG_CONN_ID,
    };

    driver->csd_conn->cn_esf.i->esfi_set_wrapper(
                driver->csd_conn->cn_enc_session, &driver->csd_stream_wrapper);

    lsquic_stream_wantwrite(stream, 1);

    LSQ_DEBUG("handshake stream created successfully");

  end:  /* Must return `driver' in either case */
    return (void *) driver;
}


static void
chsk_ietf_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct crypto_stream_driver *const driver = (void *) ctx;
    LSQ_DEBUG("crypto stream is closed");
}


static const char *const ihs2str[] = {
    [IHS_WANT_READ]  = "want read",
    [IHS_WANT_WRITE] = "want write",
    [IHS_STOP]       = "stop",
};


static void
continue_handshake (struct crypto_stream_driver *driver,
                            struct lsquic_stream *stream, const char *what)
{
    enum iquic_handshake_status st;

    st = driver->csd_conn->cn_esf.i->esfi_handshake(
                                        driver->csd_conn->cn_enc_session);
    LSQ_DEBUG("%s complete: %s", what, ihs2str[st]);
    switch (st)
    {
    case IHS_WANT_READ:
        lsquic_stream_wantwrite(stream, 0);
        lsquic_stream_wantread(stream, 1);
        break;
    case IHS_WANT_WRITE:
        lsquic_stream_wantwrite(stream, 1);
        lsquic_stream_wantread(stream, 0);
        break;
    default:
        assert(st == IHS_STOP);
        driver->csd_flags |= CSD_DISCARD;
        lsquic_stream_wantwrite(stream, 0);
        lsquic_stream_wantread(stream, 1);
        break;
    }
}


static void
chsk_ietf_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct crypto_stream_driver *const driver = (void *) ctx;
    ssize_t nread;
    size_t total;
    unsigned char buf[0x100];

    if (!(driver->csd_flags & CSD_DISCARD))
        continue_handshake(driver, stream, "on_read");
    else
    {
        total = 0;
        while ((nread = lsquic_stream_read(stream, buf, sizeof(buf))) > 0)
            total += nread;
        LSQ_DEBUG("discard %zu of post-handshake data", total);
    }
}


static void
chsk_ietf_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    continue_handshake((struct crypto_stream_driver *) ctx, stream, "on_write");
}


const struct lsquic_stream_if lsquic_cry_sm_if =
{
    .on_new_stream = chsk_ietf_on_new_stream,
    .on_read       = chsk_ietf_on_read,
    .on_write      = chsk_ietf_on_write,
    .on_close      = chsk_ietf_on_close,
};
