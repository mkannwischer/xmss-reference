#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#define XMSS_MLEN 32

#ifndef XMSS_SIGNATURES
    #define XMSS_SIGNATURES (1<<30)
#endif

static void hexdump(unsigned char *d, unsigned int l)
{
    for(unsigned int i=0; i<l  && i < 16;i++)
    {
        printf("%02x", d[i]);
    }
    printf("\n");
}

int test_case(const char *name, int xmssmt, int num_tests){
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i;
    if(xmssmt){
        xmssmt_str_to_oid(&oid, name);
        xmssmt_parse_oid(&params, oid);
    }
    else {
        xmss_str_to_oid(&oid, name);
        xmss_parse_oid(&params, oid);
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;
    randombytes(m, XMSS_MLEN);

    printf("sk_bytes=%llu + oid\n", params.sk_bytes);
    if(xmssmt){
        xmssmt_keypair(pk, sk, oid);
    }
    else {
        xmss_keypair(pk, sk, oid);
    }

    printf("pk="); hexdump(pk, sizeof pk);
    printf("sk="); hexdump(sk, sizeof sk);
    printf("Testing %d %s signatures.. \n", XMSS_SIGNATURES, name);

    for (i = 0; i < num_tests; i++) {
        printf("  - iteration #%d:\n", i);

        if(xmssmt){
            xmssmt_sign(sk, sm, &smlen, m, XMSS_MLEN);
        }
        else {
            xmss_sign(sk, sm, &smlen, m, XMSS_MLEN);
        }

        printf("sm="); hexdump(sm, smlen);

        if (smlen != params.sig_bytes + XMSS_MLEN) {
            printf("  X smlen incorrect [%llu != %u]!\n",
                   smlen, params.sig_bytes);
            ret = -1;
        }
        else {
            printf("    smlen as expected [%llu].\n", smlen);
        }

        /* Test if signature is valid. */

        if(xmssmt){
            ret = xmssmt_sign_open(mout, &mlen, sm, smlen, pk);
        }
        else {
            ret = xmss_sign_open(mout, &mlen, sm, smlen, pk);
        }
        if (ret) {
            printf("  X verification failed!\n");
        }
        else {
            printf("    verification succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (mlen != XMSS_MLEN) {
            printf("  X mlen incorrect [%llu != %u]!\n", mlen, XMSS_MLEN);
            ret = -1;
        }
        else {
            printf("    mlen as expected [%llu].\n", mlen);
        }
        if (memcmp(m, mout, XMSS_MLEN)) {
            printf("  X output message incorrect!\n");
            ret = -1;
        }
        else {
            printf("    output message as expected.\n");
        }

        if(ret) return ret;
    }
    free(m);
    free(sm);
    free(mout);
    return 0;
}

int main()
{
    int rc;
    // test XMSS
    rc = test_case("XMSS-SHA2_10_256", 0, 1<<10);
    if(rc) return rc;

    // test XMSSMT d=2
    rc = test_case("XMSSMT-SHA2_12/2_256", 1, 1<<10);
    if(rc) return rc;

    // test XMSSMT d=3
    rc = test_case("XMSSMT-SHA2_12/3_256", 1, 1<<10);
    if(rc) return rc;

    rc = test_case("XMSSMT-SHA2_22/2_256", 1, 1<<10);
    if(rc) return rc;
    return 0;
}
