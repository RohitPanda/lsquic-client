/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_enc_sess_ietf.c -- Crypto session for IETF QUIC
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/chacha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "lsquic_types.h"
#include "lsquic_hkdf.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_parse.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_in.h"
#include "lsquic_util.h"
#include "lsquic_byteswap.h"
#include "lsquic_ev_log.h"
#include "lsquic_bio_adapter.h"
#include "lsquic_trans_params.h"
#include "lsquic_engine_public.h"
#include "lsquic_version.h"
#include "lsquic_ver_neg.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HANDSHAKE
#define LSQUIC_LOG_CONN_ID &enc_sess->esi_conn->cn_scid
#include "lsquic_logger.h"

/* [draft-ietf-quic-tls-11] Section 5.3.2 */
#define HSK_SECRET_SZ SHA256_DIGEST_LENGTH

/* TODO: Specify ciphers */
#define HSK_CIPHERS "TLS13-AES-128-GCM-SHA256"  \
                   ":TLS13-AES-256-GCM-SHA384"  \
                   ":TLS13-CHACHA20-POLY1305-SHA256"

#define KEY_LABEL "key"
#define KEY_LABEL_SZ (sizeof(KEY_LABEL) - 1)
#define IV_LABEL "iv"
#define IV_LABEL_SZ (sizeof(IV_LABEL) - 1)
#define PN_LABEL "pn"
#define PN_LABEL_SZ (sizeof(PN_LABEL) - 1)
#define CLIENT_1RTT_LABEL "EXPORTER-QUIC client 1rtt"
#define CLIENT_1RTT_LABEL_SZ (sizeof(CLIENT_1RTT_LABEL) - 1)
#define SERVER_1RTT_LABEL "EXPORTER-QUIC server 1rtt"
#define SERVER_1RTT_LABEL_SZ (sizeof(SERVER_1RTT_LABEL) - 1)

/* This is seems to be true for all of the ciphers used by IETF QUIC.
 * XXX: Perhaps add a check?
 */
#define IQUIC_TAG_LEN 16

struct enc_sess_iquic;
struct crypto_ctx;
struct crypto_ctx_pair;

static int
setup_handshake_keys (struct enc_sess_iquic *, const lsquic_cid_t *);


typedef void (*encrypt_pn_f)(struct enc_sess_iquic *,
    const struct crypto_ctx *, const struct crypto_ctx_pair *,
    const unsigned char *iv, const unsigned char *src,
    unsigned char *dst, unsigned packno_len);

typedef lsquic_packno_t (*decrypt_pn_f)(struct enc_sess_iquic *,
    const struct crypto_ctx *, const struct crypto_ctx_pair *,
    const unsigned char *iv, const unsigned char *src,
    unsigned char *dst, unsigned sz, unsigned *packno_len);


struct crypto_ctx
{
    EVP_AEAD_CTX        yk_aead_ctx;
    unsigned            yk_key_sz;
    unsigned            yk_iv_sz;
    unsigned            yk_pn_sz;
    enum {
        YK_INITED = 1 << 0,
    }                   yk_flags;
    unsigned char       yk_key_buf[EVP_MAX_KEY_LENGTH];
    unsigned char       yk_iv_buf[EVP_MAX_IV_LENGTH];
    unsigned char       yk_pn_buf[EVP_MAX_KEY_LENGTH];
};


struct crypto_ctx_pair
{
    char                ykp_label[0x20];
    lsquic_packno_t     ykp_thresh;
    enum enc_level      ykp_enc_level;
    const EVP_CIPHER   *ykp_pn;
    encrypt_pn_f        ykp_encrypt_pn;
    decrypt_pn_f        ykp_decrypt_pn;
    struct crypto_ctx   ykp_ctx[2]; /* client, server */
};


/* [draft-ietf-quic-tls-12] Section 5.3.6 */
static int
init_crypto_ctx (struct crypto_ctx *crypto_ctx, const EVP_MD *md,
                 const EVP_AEAD *aead, const unsigned char *secret,
                 size_t secret_sz, enum evp_aead_direction_t dir)
{
    crypto_ctx->yk_key_sz = EVP_AEAD_key_length(aead);
    crypto_ctx->yk_iv_sz = EVP_AEAD_nonce_length(aead);
    crypto_ctx->yk_pn_sz = EVP_AEAD_key_length(aead);

    if (crypto_ctx->yk_key_sz > sizeof(crypto_ctx->yk_key_buf)
        || crypto_ctx->yk_iv_sz > sizeof(crypto_ctx->yk_iv_buf))
    {
        return -1;
    }

    lsquic_qhkdf_expand(md, secret, secret_sz, KEY_LABEL, KEY_LABEL_SZ,
        crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, IV_LABEL, IV_LABEL_SZ,
        crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, PN_LABEL, PN_LABEL_SZ,
        crypto_ctx->yk_pn_buf, crypto_ctx->yk_pn_sz);
    if (!EVP_AEAD_CTX_init_with_direction(&crypto_ctx->yk_aead_ctx, aead,
            crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz, IQUIC_TAG_LEN, dir))
        return -1;

    crypto_ctx->yk_flags |= YK_INITED;

    return 0;
}


static void
cleanup_crypto_ctx (struct crypto_ctx *crypto_ctx)
{
    if (crypto_ctx->yk_flags & YK_INITED)
    {
        EVP_AEAD_CTX_cleanup(&crypto_ctx->yk_aead_ctx);
        crypto_ctx->yk_flags &= ~YK_INITED;
    }
}


struct enc_sess_iquic
{
    struct lsquic_engine_public
                        *esi_enpub;
    struct lsquic_conn  *esi_conn;
    const struct ver_neg
                        *esi_ver_neg;
    SSL                 *esi_ssl;

    /* md, aead, pn, key_sz, and iv_sz can be used if ESI_HANDSHAKE_OK is set */
    const EVP_MD        *esi_md;
    const EVP_AEAD      *esi_aead;
    const EVP_CIPHER    *esi_pn;
    unsigned             esi_key_sz,
                         esi_iv_sz;
    encrypt_pn_f         esi_encrypt_pn;
    decrypt_pn_f         esi_decrypt_pn;

    struct crypto_ctx_pair
                         esi_crypto_pair[2]; /* current and previous/next */
    unsigned             esi_cur_pair;       /* Index into esi_crypto_pair */
    enum {
        ESI_INITIALIZED  = 1 << 0,
        ESI_LOG_SECRETS  = 1 << 1,
        ESI_HANDSHAKE_OK = 1 << 2,
    }                    esi_flags;
    enum evp_aead_direction_t
                         esi_dir[2];        /* client, server */
    enum header_type     esi_header_type;
};


static void
encrypt_pn_aes (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned packno_len)
{
    EVP_CIPHER_CTX pn_ctx;
    int out_len;

    EVP_CIPHER_CTX_init(&pn_ctx);
    if (!EVP_EncryptInit_ex(&pn_ctx, pair->ykp_pn, NULL,
                                                    crypto_ctx->yk_pn_buf, iv))
        goto err;
    if (!EVP_EncryptUpdate(&pn_ctx, dst, &out_len, src, packno_len))
        goto err;
    if (!EVP_EncryptFinal_ex(&pn_ctx, dst + out_len, &out_len))
        goto err;
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);
    return;

  err:
    LSQ_WARN("cannot encrypt packet number, error code: %"PRIu32,
                                                            ERR_get_error());
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);
}


static lsquic_packno_t
decode_packno (const unsigned char buf[4], unsigned *packno_len)
{
    lsquic_packno_t packno;

    switch (buf[0] & 0xC0)
    {
    case 0x00:
    case 0x40:
        *packno_len = 1;
        packno = buf[0] & 0x7F;
        break;
    case 0x80:
        *packno_len = 2;
        packno = ((buf[0] & 0x3F) << 8)
               |   buf[1];
        break;
    default:
        *packno_len = 4;
        packno = ((buf[0] & 0x3F) << 24)
               | ( buf[1]         << 16)
               | ( buf[2]         <<  8)
               |   buf[3];
        break;
    }

    return packno;
}


static lsquic_packno_t
decrypt_pn_aes (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned sz, unsigned *packno_len)
{
    int out_len, packno_buflen;
    EVP_CIPHER_CTX pn_ctx;

    EVP_CIPHER_CTX_init(&pn_ctx);
    if (!EVP_DecryptInit_ex(&pn_ctx, pair->ykp_pn, NULL,
                                                    crypto_ctx->yk_pn_buf, iv))
        goto err;
    if (!EVP_DecryptUpdate(&pn_ctx, dst, &out_len, src, sz))
        goto err;
    packno_buflen = out_len;
    if (!EVP_DecryptFinal_ex(&pn_ctx, dst + out_len, &out_len))
        goto err;
    packno_buflen += out_len;
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);

    if (packno_buflen != 4)
    {
        LSQ_INFO("decrypt: packet number buffer is not 4 bytes long as "
            "expected");
        goto err;   /* XXX */
    }

    return decode_packno(dst, packno_len);

  err:
    LSQ_WARN("cannot decrypt packet number, error code: %"PRIu32,
                                                            ERR_get_error());
    (void) EVP_CIPHER_CTX_cleanup(&pn_ctx);
    return IQUIC_INVALID_PACKNO;
}


static void
encrypt_pn_chacha20 (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned sz)
{
    const uint8_t *nonce;
    uint32_t counter;

    memcpy(&counter, iv, sizeof(counter));
    nonce = iv + sizeof(counter);
    CRYPTO_chacha_20(dst, src, sz, crypto_ctx->yk_pn_buf, nonce, counter);
}


static lsquic_packno_t
decrypt_pn_chacha20 (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, const unsigned char *src, unsigned char *dst,
        unsigned sz, unsigned *packno_len)
{
    const uint8_t *nonce;
    uint32_t counter;

    memcpy(&counter, iv, sizeof(counter));
    nonce = iv + sizeof(counter);
    CRYPTO_chacha_20(dst, src, sz, crypto_ctx->yk_pn_buf, nonce, counter);
    return decode_packno(dst, packno_len);
}


static int
gen_trans_params (struct enc_sess_iquic *enc_sess, unsigned char *buf,
                                                                size_t bufsz)
{
    const struct lsquic_engine_settings *const settings =
                                    &enc_sess->esi_enpub->enp_settings;
    struct transport_params params;
    int len;

    memset(&params, 0, sizeof(params));
    params.tp_version_u.client.initial =
                                lsquic_ver2tag(enc_sess->esi_ver_neg->vn_ver);
    params.tp_init_max_data = settings->es_initial_max_data;
    params.tp_init_max_stream_data
                            = settings->es_initial_max_stream_data;
    params.tp_init_max_uni_streams
                            = settings->es_initial_max_streams_uni;
    params.tp_init_max_bidi_streams
                            = settings->es_initial_max_streams_bidi;
    params.tp_ack_delay_exponent
                            = settings->es_ack_delay_exp;
    params.tp_idle_timeout  = settings->es_idle_timeout;
    params.tp_max_packet_size = 1370 /* XXX: based on socket */;

    len = lsquic_tp_encode(&params, buf, bufsz);
    if (len >= 0)
        LSQ_DEBUG("generated transport parameters buffer of %d bytes", len);
    else
        LSQ_WARN("cannot generate transport parameters: %d", errno);
    return len;
}


static void
generate_cid (lsquic_cid_t *cid, int len)
{
    if (!len)
        /* If not set, generate ID between 8 and MAX_CID_LEN bytes in length */
        len = 8 + rand() % (MAX_CID_LEN - 7);
    RAND_bytes(cid->idbuf, len);
    cid->len = len;
}


static enc_session_t *
iquic_esfi_create_client (struct lsquic_engine_public *enpub,
                struct lsquic_conn *lconn, const struct ver_neg *ver_neg)
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = calloc(1, sizeof(*enc_sess));
    if (!enc_sess)
        return NULL;

    enc_sess->esi_enpub = enpub;
    enc_sess->esi_conn = lconn;
    enc_sess->esi_ver_neg = ver_neg;
    generate_cid(&lconn->cn_dcid, 0);

    enc_sess->esi_dir[0] = evp_aead_seal;
    enc_sess->esi_dir[1] = evp_aead_open;
    enc_sess->esi_header_type = HETY_INITIAL;

    LSQ_DEBUGC("created client, DCID: %"CID_FMT, CID_BITS(&lconn->cn_dcid));
    {
        const char *log;
        log = getenv("LSQUIC_LOG_SECRETS");
        if (log)
        {
            if (atoi(log))
                enc_sess->esi_flags |= ESI_LOG_SECRETS;
            LSQ_DEBUG("will %slog secrets", atoi(log) ? "" : "not ");
        }
    }

    if (0 != setup_handshake_keys(enc_sess, &lconn->cn_dcid))
    {
        free(enc_sess);
        return NULL;
    }

    return enc_sess;
}


static void
log_crypto_pair (const struct enc_sess_iquic *enc_sess,
                    const struct crypto_ctx_pair *pair, const char *name)
{
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];
    LSQ_DEBUG("client %s key: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_key_buf, pair->ykp_ctx[0].yk_key_sz,
                                                                hexbuf));
    LSQ_DEBUG("client %s iv: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_iv_buf, pair->ykp_ctx[0].yk_iv_sz,
                                                                hexbuf));
    LSQ_DEBUG("client %s pn: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_pn_buf, pair->ykp_ctx[0].yk_pn_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s key: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_key_buf, pair->ykp_ctx[1].yk_key_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s iv: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_iv_buf, pair->ykp_ctx[1].yk_iv_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s pn: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_pn_buf, pair->ykp_ctx[1].yk_pn_sz,
                                                                hexbuf));
}


/* [draft-ietf-quic-tls-12] Section 5.3.2 */
static int
setup_handshake_keys (struct enc_sess_iquic *enc_sess, const lsquic_cid_t *cid)
{
    const EVP_MD *const md = EVP_sha256();
    const EVP_AEAD *const aead = EVP_aead_aes_128_gcm();
    struct crypto_ctx_pair *const pair =
                        &enc_sess->esi_crypto_pair[ enc_sess->esi_cur_pair ];
    unsigned hsk_secret_sz;
    unsigned char hsk_secret[EVP_MAX_MD_SIZE];
    unsigned char secret[2][SHA256_DIGEST_LENGTH];  /* client, server */
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];

    lsquic_hkdf_extract(md, cid->idbuf, cid->len, HSK_SALT, HSK_SALT_SZ,
                hsk_secret, &hsk_secret_sz);
    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
    {
        LSQ_DEBUG("handshake salt: %s", HEXSTR(HSK_SALT, HSK_SALT_SZ, hexbuf));
        LSQ_DEBUG("handshake secret: %s", HEXSTR(hsk_secret, hsk_secret_sz,
                                                                    hexbuf));
    }

    lsquic_qhkdf_expand(md, hsk_secret, hsk_secret_sz, CLIENT_LABEL,
                CLIENT_LABEL_SZ, secret[0], sizeof(secret[0]));
    LSQ_DEBUG("client handshake secret: %s",
        HEXSTR(secret[0], sizeof(secret[0]), hexbuf));
    if (0 != init_crypto_ctx(&pair->ykp_ctx[0], md, aead, secret[0],
                sizeof(secret[0]), enc_sess->esi_dir[0]))
        goto err;
    lsquic_qhkdf_expand(md, hsk_secret, hsk_secret_sz, SERVER_LABEL,
                SERVER_LABEL_SZ, secret[1], sizeof(secret[1]));
    LSQ_DEBUG("server handshake secret: %s",
        HEXSTR(secret[1], sizeof(secret[1]), hexbuf));
    if (0 != init_crypto_ctx(&pair->ykp_ctx[1], md, aead, secret[1],
                sizeof(secret[1]), enc_sess->esi_dir[1]))
        goto err;

    /* [draft-ietf-quic-tls-12] Section 5.6.1: AEAD_AES_128_GCM implies
     * 128-bit AES-CTR.
     */
    pair->ykp_pn = EVP_aes_128_ctr();
    pair->ykp_encrypt_pn = encrypt_pn_aes;
    pair->ykp_decrypt_pn = decrypt_pn_aes;

    pair->ykp_enc_level = ENC_LEV_CLEAR;
    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
        log_crypto_pair(enc_sess, pair, "handshake");

    return 0;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    return -1;
}


static int
iquic_esfi_init_client (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    SSL_CTX *ssl_ctx;
    BIO *bio;
    int transpa_len;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf   /* This is a dual-purpose buffer */
    unsigned char trans_params[0x80];

    ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx)
    {
        LSQ_ERROR("cannot create SSL context: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(ssl_ctx);

    transpa_len = gen_trans_params(enc_sess, trans_params,
                                                    sizeof(trans_params));
    if (transpa_len < 0)
    {
        SSL_CTX_free(ssl_ctx);
        goto err;
    }

    enc_sess->esi_ssl = SSL_new(ssl_ctx);
    if (!enc_sess->esi_ssl)
    {
        SSL_CTX_free(ssl_ctx);
        LSQ_ERROR("cannot create SSL object: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (1 != SSL_set_quic_transport_params(enc_sess->esi_ssl, trans_params,
                                                            transpa_len))
    {
        LSQ_ERROR("cannot set QUIC transport params: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    bio = BIO_new(lsquic_bio_adapter);
    if (!bio)
    {
        LSQ_ERROR("cannot create BIO object: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    BIO_set_init(bio, 1);
    SSL_set_bio(enc_sess->esi_ssl, bio, bio);
    SSL_set_app_data(enc_sess->esi_ssl, enc_sess);
    SSL_set_connect_state(enc_sess->esi_ssl);

    LSQ_DEBUG("initialized client enc session");
    enc_sess->esi_flags |= ESI_INITIALIZED;
    return 0;

  err:
    return -1;
#undef hexbuf
}


static void
iquic_esfi_set_wrapper (enc_session_t *enc_session_p,
                                            struct stream_wrapper *stream)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    BIO *bio;

    bio = SSL_get_rbio(enc_sess->esi_ssl);
    BIO_set_data(bio, stream);
    bio = SSL_get_wbio(enc_sess->esi_ssl);
    BIO_set_data(bio, stream);
}


static int
set_md_and_aead (struct enc_sess_iquic *enc_sess)
{
    const SSL_CIPHER *cipher;
    const EVP_AEAD *aead;
    const EVP_MD *md;
    const EVP_CIPHER *pn;
    encrypt_pn_f enc_pn_f;
    decrypt_pn_f dec_pn_f;
    unsigned key_sz, iv_sz;
    uint32_t id;

    cipher = SSL_get_current_cipher(enc_sess->esi_ssl);
    id = SSL_CIPHER_get_id(cipher);

    LSQ_DEBUG("Negotiated cipher ID is 0x%"PRIX32, id);

    /* [draft-ietf-tls-tls13-28] Appendix B.4 */
    switch (id)
    {
    case 0x03000000 | 0x1301:       /* TLS_AES_128_GCM_SHA256 */
        md   = EVP_sha384();
        aead = EVP_aead_aes_128_gcm();
        pn   = EVP_aes_128_ctr();
        enc_pn_f = encrypt_pn_aes;
        dec_pn_f = decrypt_pn_aes;
        break;
    case 0x03000000 | 0x1302:       /* TLS_AES_256_GCM_SHA384 */
        md   = EVP_sha384();
        aead = EVP_aead_aes_256_gcm();
        pn   = EVP_aes_256_ctr();
        enc_pn_f = encrypt_pn_aes;
        dec_pn_f = decrypt_pn_aes;
        break;
    case 0x03000000 | 0x1303:       /* TLS_CHACHA20_POLY1305_SHA256 */
        md   = EVP_sha256();
        aead = EVP_aead_chacha20_poly1305();
        pn   = NULL;
        enc_pn_f = encrypt_pn_chacha20;
        dec_pn_f = decrypt_pn_chacha20;
        break;
    default:
        /* TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256 are not
         * supported by BoringSSL (grep for \b0x130[45]\b).
         */
        LSQ_DEBUG("unsupported cipher 0x%"PRIX32, id);
        return -1;
    }

    key_sz = EVP_AEAD_key_length(aead);
    if (key_sz > sizeof(enc_sess->esi_crypto_pair[0].ykp_ctx[0].yk_key_buf))
    {
        LSQ_DEBUG("key size %u is too large", key_sz);
        return -1;
    }

    iv_sz = EVP_AEAD_nonce_length(aead);
    if (iv_sz < 8)
        iv_sz = 8;  /* [draft-ietf-quic-tls-11], Section 5.3 */
    if (iv_sz > sizeof(enc_sess->esi_crypto_pair[0].ykp_ctx[0].yk_iv_buf))
    {
        LSQ_DEBUG("iv size %u is too large", iv_sz);
        return -1;
    }

    if (key_sz > sizeof(enc_sess->esi_crypto_pair[0].ykp_ctx[0].yk_pn_buf))
    {
        LSQ_DEBUG("PN size %u is too large", key_sz);
        return -1;
    }

    enc_sess->esi_md     = md;
    enc_sess->esi_aead   = aead;
    enc_sess->esi_pn     = pn;
    enc_sess->esi_encrypt_pn = enc_pn_f;
    enc_sess->esi_decrypt_pn = dec_pn_f;
    enc_sess->esi_key_sz = key_sz;
    enc_sess->esi_iv_sz  = iv_sz;

    return 0;
}


static int
derive_1rtt_keys (struct enc_sess_iquic *enc_sess)
{
    struct crypto_ctx_pair *pair;
    unsigned next_pair, secret_sz;
    static const struct {
        const char *str;
        size_t      sz;
    } labels[] = {
        { CLIENT_1RTT_LABEL, CLIENT_1RTT_LABEL_SZ, },
        { SERVER_1RTT_LABEL, SERVER_1RTT_LABEL_SZ, },
    };
    int i;
    unsigned char secret[2][EVP_MAX_MD_SIZE];
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf

    secret_sz = EVP_MD_size(enc_sess->esi_md);

    next_pair = !enc_sess->esi_cur_pair;
    pair = &enc_sess->esi_crypto_pair[next_pair];

    for (i = 1; i >= 0; --i)
    {
        cleanup_crypto_ctx(&pair->ykp_ctx[i]);
        if (1 != SSL_export_keying_material(enc_sess->esi_ssl, secret[i],
                    secret_sz, labels[i].str, labels[i].sz, NULL, 0, 1))
        {
            LSQ_WARN("export `%s' failed: %s", labels[i].str,
                ERR_error_string(ERR_get_error(), errbuf));
            goto err;
        }
        if (enc_sess->esi_flags & ESI_LOG_SECRETS)
            LSQ_DEBUG("1rtt %s secret: %s", i ? "server" : "client",
                HEXSTR(secret[i], secret_sz, hexbuf));
        if (0 != init_crypto_ctx(&pair->ykp_ctx[i], enc_sess->esi_md,
                    enc_sess->esi_aead, secret[i], secret_sz,
                    enc_sess->esi_dir[i]))
            goto err;
    }

    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
        log_crypto_pair(enc_sess, pair, "1rtt");

    pair->ykp_enc_level = ENC_LEV_FORW;
    pair->ykp_pn = enc_sess->esi_pn;
    pair->ykp_encrypt_pn = enc_sess->esi_encrypt_pn;
    pair->ykp_decrypt_pn = enc_sess->esi_decrypt_pn;
    enc_sess->esi_cur_pair = next_pair;
    return 0;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    return -1;
#undef hexbuf
}


static enum iquic_handshake_status
iquic_esfi_handshake (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    int s, err;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    s = SSL_do_handshake(enc_sess->esi_ssl);
    if (s <= 0)
    {
        err = SSL_get_error(enc_sess->esi_ssl, s);
        switch (err)
        {
        case SSL_ERROR_WANT_READ:
            LSQ_DEBUG("retry read");
            return IHS_WANT_READ;
        case SSL_ERROR_WANT_WRITE:
            LSQ_DEBUG("retry write");
            return IHS_WANT_WRITE;
        default:
            LSQ_DEBUG("handshake: %s", ERR_error_string(err, errbuf));
            goto err;
        }
    }

    LSQ_DEBUG("handshake reported complete");

    if (0 != set_md_and_aead(enc_sess))
        goto err;

    if (0 != derive_1rtt_keys(enc_sess))
        goto err;

    enc_sess->esi_header_type = HETY_HANDSHAKE;
    enc_sess->esi_flags |= ESI_HANDSHAKE_OK;
    enc_sess->esi_conn->cn_if->ci_handshake_ok(enc_sess->esi_conn);

    return IHS_STOP;    /* XXX: what else can come on the crypto stream? */

  err:
    LSQ_DEBUG("handshake failed");
    enc_sess->esi_conn->cn_if->ci_handshake_failed(enc_sess->esi_conn);
    return IHS_STOP;
}


static int
iquic_esfi_get_peer_transport_params (enc_session_t *enc_session_p,
                                        struct transport_params *trans_params)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    const uint8_t *params_buf;
    size_t bufsz;

    if (!(enc_sess->esi_flags & ESI_HANDSHAKE_OK))
        return -1;

    SSL_get_peer_quic_transport_params(enc_sess->esi_ssl, &params_buf, &bufsz);
    if (!params_buf)
    {
        LSQ_DEBUG("no peer transport parameters");
        return -1;
    }

    LSQ_DEBUG("have peer transport parameters (%zu bytes)", bufsz);
    if (0 > lsquic_tp_decode(params_buf, bufsz,
                                                trans_params))
    {
        LSQ_DEBUG("could not parse peer transport parameters");
        return -1;
    }

    return 0;
}


static void
iquic_esfi_destroy (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    LSQ_DEBUG("destroy client handshake object");
    if (enc_sess->esi_ssl)
        SSL_free(enc_sess->esi_ssl);
    free(enc_sess);
}


static enum enc_packout
iquic_esf_encrypt_packet (enc_session_t *enc_session_p,
    const struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
    struct lsquic_packet_out *packet_out)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    unsigned char *dst;
    const struct crypto_ctx_pair *pair;
    const struct crypto_ctx *crypto_ctx;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    lsquic_packno_t packno;
    size_t out_sz, dst_sz;
    int header_sz;
    unsigned pair_idx, packno_off, packno_len, sample_off;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    assert(lconn == enc_sess->esi_conn);

    packet_out->po_header_type = enc_sess->esi_header_type;
    dst_sz = lconn->cn_pf->pf_packout_size(lconn, packet_out);
    dst = enpub->enp_pmi->pmi_allocate(enpub->enp_pmi_ctx, dst_sz);
    if (!dst)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        dst_sz);
        return ENCPA_NOMEM;
    }

    if (0 == (packet_out->po_flags & PO_HELLO))
        pair_idx = enc_sess->esi_cur_pair;
    else
        pair_idx = 0;

    pair = &enc_sess->esi_crypto_pair[ pair_idx ];
    crypto_ctx = &pair->ykp_ctx[ 0 ];

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    packno = packet_out->po_packno;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    header_sz = lconn->cn_pf->pf_gen_reg_pkt_header(lconn, packet_out, dst,
                                                                        dst_sz);
    if (header_sz < 0)
        goto err;

    if (!EVP_AEAD_CTX_seal(&crypto_ctx->yk_aead_ctx, dst + header_sz, &out_sz,
                dst_sz - header_sz, nonce, crypto_ctx->yk_iv_sz, packet_out->po_data,
                packet_out->po_data_sz, dst, header_sz))
    {
        LSQ_WARN("cannot seal packet #%"PRIu64": %s", packet_out->po_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    assert(out_sz == dst_sz - header_sz);

    lconn->cn_pf->pf_packno_info(lconn, packet_out, &packno_off, &packno_len);
    sample_off = packno_off + 4;
    if (sample_off + IQUIC_TAG_LEN > dst_sz)
        sample_off = dst_sz - IQUIC_TAG_LEN;
    pair->ykp_encrypt_pn(enc_sess, crypto_ctx, pair, dst + sample_off,
                             dst + packno_off, dst + packno_off, packno_len);

    packet_out->po_enc_data    = dst;
    packet_out->po_enc_data_sz = dst_sz;
    packet_out->po_sent_sz     = dst_sz;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ;

    return ENCPA_OK;

  err:
    enpub->enp_pmi->pmi_release(enpub->enp_pmi_ctx, dst);
    return ENCPA_BADCRYPT;
}


static int
iquic_esf_decrypt_packet (enc_session_t *enc_session_p,
        struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
        struct lsquic_packet_in *packet_in)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    unsigned char *dst;
    const struct crypto_ctx_pair *pair;
    const struct crypto_ctx *crypto_ctx;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    unsigned sample_off, packno_len;
    lsquic_packno_t packno;
    size_t out_sz;
    const size_t dst_sz = 1370;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    dst = lsquic_mm_get_1370(&enpub->enp_mm);
    if (!dst)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        goto err;
    }

    pair = &enc_sess->esi_crypto_pair[ enc_sess->esi_cur_pair ];
    crypto_ctx = &pair->ykp_ctx[ 1 ];

    /* Decrypt packet number.  After this operation, packet_in is adjusted:
     * the packet number becomes part of the header.
     */
    sample_off = packet_in->pi_header_sz + 4;
    if (sample_off + IQUIC_TAG_LEN > packet_in->pi_data_sz)
        sample_off = packet_in->pi_data_sz - IQUIC_TAG_LEN;
    packet_in->pi_packno =
    packno = pair->ykp_decrypt_pn(enc_sess, crypto_ctx, pair,
        packet_in->pi_data + sample_off,
        packet_in->pi_data + packet_in->pi_header_sz,
        /* TODO: check that there is enough room in dst */
        dst + packet_in->pi_header_sz, 4, &packno_len);

    /* TODO: check that returned packno is valid */

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    memcpy(dst, packet_in->pi_data, packet_in->pi_header_sz);
    packet_in->pi_header_sz += packno_len;

    if (!EVP_AEAD_CTX_open(&crypto_ctx->yk_aead_ctx,
                dst + packet_in->pi_header_sz, &out_sz,
                dst_sz - packet_in->pi_header_sz, nonce, crypto_ctx->yk_iv_sz,
                packet_in->pi_data + packet_in->pi_header_sz,
                packet_in->pi_data_sz - packet_in->pi_header_sz,
                dst, packet_in->pi_header_sz))
    {
        LSQ_WARN("cannot open packet #%"PRIu64": %s", packet_in->pi_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    packet_in->pi_data_sz = packet_in->pi_header_sz + out_sz;
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_1370(&enpub->enp_mm, packet_in->pi_data);
    packet_in->pi_data = dst;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (pair->ykp_enc_level << PIBIT_ENC_LEV_SHIFT);
    EV_LOG_CONN_EVENT(&lconn->cn_cid, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
    return 0;

  err:
    if (dst)
        lsquic_mm_put_1370(&enpub->enp_mm, dst);
    EV_LOG_CONN_EVENT(&lconn->cn_cid, "could not decrypt packet %"PRIu64,
                                                    packet_in->pi_packno);
    return -1;
}


static void
iquic_esfi_assign_scid (const struct lsquic_engine_public *enpub,
                                                    struct lsquic_conn *lconn)
{
    generate_cid(&lconn->cn_scid, enpub->enp_settings.es_scid_len);
    LSQ_LOG1C(LSQ_LOG_DEBUG, "generated and assigned SCID %"CID_FMT,
                                                    CID_BITS(&lconn->cn_scid));
}


const struct enc_session_funcs_iquic lsquic_enc_session_iquic_id12 =
{
    .esfi_assign_scid    = iquic_esfi_assign_scid,
    .esfi_create_client  = iquic_esfi_create_client,
    .esfi_destroy        = iquic_esfi_destroy,
    .esfi_init_client    = iquic_esfi_init_client,
    .esfi_set_wrapper    = iquic_esfi_set_wrapper,
    .esfi_handshake      = iquic_esfi_handshake,
    .esfi_get_peer_transport_params
                         = iquic_esfi_get_peer_transport_params,
};


const struct enc_session_funcs_common lsquic_enc_session_common_id12 =
{
    .esf_encrypt_packet  = iquic_esf_encrypt_packet,
    .esf_decrypt_packet  = iquic_esf_decrypt_packet,
    .esf_tag_len         = IQUIC_TAG_LEN,
};
