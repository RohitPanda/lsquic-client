/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stddef.h>
#include <string.h>

#include <openssl/hmac.h>

#include "lsquic_hkdf.h"


void
lsquic_hkdf_extract (const EVP_MD *md, const unsigned char *ikm,
            unsigned ikm_len, const unsigned char *salt, unsigned salt_len,
            unsigned char *prk, unsigned *prk_len)
{
    HMAC(md, salt, salt_len, ikm, ikm_len, prk, prk_len);
}


void
lsquic_hkdf_expand (const EVP_MD *md, const unsigned char *prk,
            unsigned prk_len, const unsigned char *info, unsigned info_len,
            unsigned char *okm, unsigned okm_len)
{
    const size_t md_sz = EVP_MD_size(md);
    unsigned char *out = okm;
    unsigned char *const end = okm + okm_len;
    const unsigned char *input;
    size_t input_sz;
    unsigned idx;
    unsigned char ikm[2][ md_sz + info_len + 1 ];

    assert(okm_len <= 255 * md_sz);         /* RFC 5869, Section 2.3 */

    idx = 0;
    memcpy(ikm[idx] + md_sz, info, info_len);
    ikm[idx][md_sz + info_len] = 1;
    input = ikm[idx] + md_sz;
    input_sz = info_len + 1;

    while (1)
    {
        HMAC(md, prk, prk_len, input, input_sz, ikm[ !idx ], NULL);

        if ((unsigned) (end - out) > md_sz)
        {
            memcpy(out, ikm[ !idx ], md_sz);
            out += md_sz;
            if (!idx)
                memcpy(ikm[1] + md_sz, info, info_len);
            ++idx;
            ikm[idx & 1][md_sz + info_len] = idx + 1;
            input = ikm[idx & 1];
            input_sz = sizeof(ikm[idx & 1]);
        }
        else
        {
            memcpy(out, ikm[ !idx ], end - out);
            break;
        }
    }
}


/* [draft-ietf-quic-tls-12] Section 5.3.1 */
void
lsquic_qhkdf_expand (const EVP_MD *md, const unsigned char *secret,
            unsigned secret_len, const char *label, uint8_t label_len,
            unsigned char *out, uint16_t out_len)
{
    unsigned char info[ 2 + 1 + 5 + label_len ];

    info[0] = out_len >> 8;
    info[1] = out_len;
    info[2] = label_len + 5;
    info[3] = 'Q';
    info[4] = 'U';
    info[5] = 'I';
    info[6] = 'C';
    info[7] = ' ';
    memcpy(info + 8, label, label_len);
    lsquic_hkdf_expand(md, secret, secret_len, info, sizeof(info), out,
                                                                    out_len);
}
