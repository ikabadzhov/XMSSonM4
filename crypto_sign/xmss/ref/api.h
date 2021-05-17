#ifndef XMSS_API_H
#define XMSS_API_H

#include "params.h"

#define CRYPTO_ALGNAME "XMSS"

#define XMSS_PK_BYTES 64

#define CRYPTO_SECRETKEYBYTES XMSS_SK_BYTES + XMSS_OID_LEN
#define CRYPTO_PUBLICKEYBYTES XMSS_PK_BYTES + XMSS_OID_LEN
#define CRYPTO_BYTES XMSS_BYTES

/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [OID || (32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [OID || root || PUB_SEED]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/**
 * Signs a message using an XMSS secret key.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                unsigned char *sk);

/**
 * Verifies a given message signature pair using a given public key.
 *
 * Note: m and mlen are pure outputs which carry the message in case
 * verification succeeds. The (input) message is assumed to be contained in sm
 * which has the form [signature || message].
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif
