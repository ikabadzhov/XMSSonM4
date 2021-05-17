#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

#ifndef H
#define H 0 // {0, 1, 2} -- corresponds to the 3 RFC required parameters for h={0:10, 1:16, 2:20}
#endif

#ifndef FAST
#define FAST 0 // {0, 1}
#endif

// from first paper, applicable for any FAST
//#define NO_BITMASK // can be commented, bitmask, relaxing the required hash function
//#define PRE_COMP  // pre-computation of the hash values
//

// from second paper, if FAST is not 2, these arguments will be ignored
//#define BLOCK 12  // {0, 1, 2} -- sha256_inc_blocks discussed in the thesis paper
//#define FASTHASH 1  // {0, 1}
#ifndef SHIFT
#define SHIFT 10 // {2, 100} -- T - main improvement from the second paper
#endif
//


// FIXED
#define PQC_SHA256CTX_BYTES 40 // default padding for SHA256 in XMSS
#define XMSS_HASH_PADDING_HASH 2 // from RFC
#define XMSS_OID_LEN 4  // from RFC, needed for parsing
#define FASTHASH // from second paper fixed
//


#if H == 0
    #define OID "XMSS-SHA256_10"
    #define XMSS_SK_BYTES 1373
    #define XMSS_BYTES 2540
#elif H == 1
    #define OID "XMSS-SHA256_16"
    #define XMSS_SK_BYTES 2093
    #define XMSS_BYTES 2692
#elif H == 2
    #define OID "XMSS-SHA256_20"
    #define XMSS_SK_BYTES 2573
    #define XMSS_BYTES 2820
#endif


/* This structure will be populated when calling xmss[mt]_parse_oid. */
typedef struct {
    unsigned int func;
    unsigned int n;
    unsigned int wots_w;
    unsigned int wots_log_w;
    unsigned int wots_len1;
    unsigned int wots_len2;
    unsigned int wots_len;
    unsigned int wots_sig_bytes;
    unsigned int full_height;
    unsigned int tree_height;
    unsigned int d;
    unsigned int index_bytes;
    unsigned int sig_bytes;
    unsigned int pk_bytes;
    unsigned long long sk_bytes;
    unsigned int bds_k;
} xmss_params;

/**
 * Accepts strings such as "XMSS-SHA2_10_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
int xmss_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts takes strings such as "XMSSMT-SHA2_20/2_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns -1 when the parameter set is not found, 0 otherwise
 */
//int xmssmt_str_to_oid(uint32_t *oid, const char *s);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
int xmss_parse_oid(xmss_params *params, const uint32_t oid);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns -1 when the OID is not found, 0 otherwise.
 */
//int xmssmt_parse_oid(xmss_params *params, const uint32_t oid);

/* Given a params struct where the following properties have been initialized;
    - full_height; the height of the complete (hyper)tree
    - n; the number of bytes of hash function output
    - d; the number of layers (d > 1 implies XMSSMT)
    - func; one of {XMSS_SHA2, XMSS_SHAKE}
    - wots_w; the Winternitz parameter
    - optionally, bds_k; the BDS traversal trade-off parameter,
    this function initializes the remainder of the params structure. */
int xmss_xmssmt_initialize_params(xmss_params *params);

#endif
