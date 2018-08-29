/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * See
 *  https://github.com/quicwg/base-drafts/wiki/Test-Vector-for-the-Clear-Text-AEAD-key-derivation
 */

#include <assert.h>
#include <string.h>

#include <openssl/ssl.h>

#include "lsquic_types.h"
#include "lsquic_hkdf.h"

int
main (void)
{
    const EVP_MD *const md = EVP_sha256();

    const lsquic_cid_t dcid = {
        .idbuf = "\x83\x94\xc8\xf0\x3e\x51\x57\x08",
        .len = 8,
    };
    unsigned char secret[100];
    unsigned secret_len;

    const unsigned char expected_secret[] = {
        0xa5, 0x72, 0xb0, 0x24, 0x5a, 0xf1, 0xed, 0xdf, 
        0x5c, 0x61, 0xc6, 0xe3, 0xf7, 0xf9, 0x30, 0x4c, 
        0xa6, 0x6b, 0xfb, 0x4c, 0xaa, 0xf7, 0x65, 0x67, 
        0xd5, 0xcb, 0x8d, 0xd1, 0xdc, 0x4e, 0x82, 0x0b,
    };

    lsquic_hkdf_extract(md, dcid.idbuf, dcid.len, HSK_SALT, HSK_SALT_SZ,
                        secret, &secret_len);

    assert(sizeof(expected_secret) == secret_len);
    assert(0 == memcmp(secret, expected_secret, sizeof(expected_secret)));

    unsigned char client_secret[32];
    const unsigned char expected_client_secret[] = {
        0x83, 0x55, 0xf2, 0x1a, 0x3d, 0x8f, 0x83, 0xec,
        0xb3, 0xd0, 0xf9, 0x71, 0x08, 0xd3, 0xf9, 0x5e,
        0x0f, 0x65, 0xb4, 0xd8, 0xae, 0x88, 0xa0, 0x61,
        0x1e, 0xe4, 0x9d, 0xb0, 0xb5, 0x23, 0x59, 0x1d,
    };
    lsquic_qhkdf_expand(md, secret, secret_len, CLIENT_LABEL, CLIENT_LABEL_SZ,
                        client_secret, sizeof(client_secret));
    assert(0 == memcmp(client_secret, expected_client_secret,
                        sizeof(client_secret)));
    const unsigned char expected_client_key[] = {
        0x3a, 0xd0, 0x54, 0x2c, 0x4a, 0x85, 0x84, 0x74,
        0x00, 0x63, 0x04, 0x9e, 0x3b, 0x3c, 0xaa, 0xb2,
    };
    const unsigned char expected_client_iv[] = {
        0xd1, 0xfd, 0x26, 0x05, 0x42, 0x75, 0x3a, 0xba,
        0x38, 0x58, 0x9b, 0xad,
    };
    unsigned char client_key[sizeof(expected_client_key)],
                  client_iv[sizeof(expected_client_iv)];
    lsquic_qhkdf_expand(md, client_secret, sizeof(client_secret), "key", 3,
                        client_key, sizeof(client_key));
    assert(0 == memcmp(client_key, expected_client_key,
                        sizeof(expected_client_key)));
    lsquic_qhkdf_expand(md, client_secret, sizeof(client_secret), "iv", 2,
                        client_iv, sizeof(client_iv));
    assert(0 == memcmp(client_iv, expected_client_iv,
                        sizeof(expected_client_iv)));

    unsigned char server_secret[32];
    const unsigned char expected_server_secret[] = {
        0xf8, 0x0e, 0x57, 0x71, 0x48, 0x4b, 0x21, 0xcd,
        0xeb, 0xb5, 0xaf, 0xe0, 0xa2, 0x56, 0xa3, 0x17,
        0x41, 0xef, 0xe2, 0xb5, 0xc6, 0xb6, 0x17, 0xba,
        0xe1, 0xb2, 0xf1, 0x5a, 0x83, 0x04, 0x83, 0xd6,
    };
    lsquic_qhkdf_expand(md, secret, secret_len, SERVER_LABEL, SERVER_LABEL_SZ,
                        server_secret, sizeof(server_secret));
    assert(0 == memcmp(server_secret, expected_server_secret,
                        sizeof(server_secret)));
    const unsigned char expected_server_key[] = {
        0xbe, 0xe4, 0xc2, 0x4d, 0x2a, 0xf1, 0x33, 0x80,
        0xa9, 0xfa, 0x24, 0xa5, 0xe2, 0xba, 0x2c, 0xff,
    };
    const unsigned char expected_server_iv[] = {
        0x25, 0xb5, 0x8e, 0x24, 0x6d, 0x9e, 0x7d, 0x5f,
        0xfe, 0x43, 0x23, 0xfe,
    };
    unsigned char server_key[sizeof(expected_server_key)],
                  server_iv[sizeof(expected_server_iv)];
    lsquic_qhkdf_expand(md, server_secret, sizeof(server_secret), "key", 3,
                        server_key, sizeof(server_key));
    assert(0 == memcmp(server_key, expected_server_key,
                        sizeof(expected_server_key)));
    lsquic_qhkdf_expand(md, server_secret, sizeof(server_secret), "iv", 2,
                        server_iv, sizeof(server_iv));
    assert(0 == memcmp(server_iv, expected_server_iv,
                        sizeof(expected_server_iv)));

    return 0;
}
