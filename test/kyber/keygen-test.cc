#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "test-api.hh"

extern "C"
{
#include "../../ref/kyber/ref/api.h"

void randombytes(uint8_t *out, size_t outlen) {}
}


int pqcrystals_kyber512_cuda_keypair(uint8_t *pk, uint8_t *sk, uint32_t keypair_count);

int kyberCudaKeyPair( uint8_t *pk, uint8_t *sk, const uint8_t *coins)
{
    // Coins are the same
    return pqcrystals_kyber512_cuda_keypair( pk, sk, 1);
}

int kyberRefKeyPair( uint8_t *pk, uint8_t *sk, const uint8_t *coins)
{
    return pqcrystals_kyber512_ref_keypair_derand( pk, sk, coins);
}

int testKeygen()
{
    uint8_t publicKeyRef[kyberPublicKeyBytes];
    uint8_t secretKeyRef[kyberSecretKeyBytes];

    uint8_t publicKeyCuda[kyberPublicKeyBytes];
    uint8_t secretKeyCuda[kyberSecretKeyBytes];

    uint8_t keyPairCoins[kyberKeyPairCoinBytes] = {
        0xcb, 0x12, 0x61, 0xa8, 0xcf, 0x85, 0xa4, 0x8b, 0x5d, 0x37, 0xc1, 0x00, 0xb6, 0xb0, 0x2c, 0xfb,
        0x1b, 0x84, 0x78, 0xc6, 0x2f, 0xe1, 0xc7, 0xd0, 0xe2, 0xcc, 0x0b, 0x48, 0xe7, 0xb7, 0xae, 0xfd,
        0x7f, 0xe1, 0xa8, 0x95, 0xdb, 0xd9, 0x28, 0x88, 0x12, 0xf2, 0x68, 0xc0, 0x84, 0x8e, 0xe0, 0xa6,
        0x1f, 0xe5, 0xd3, 0x21, 0xbb, 0xcf, 0x6d, 0x3c, 0x98, 0xb5, 0x35, 0xc4, 0x74, 0xae, 0x1a, 0xb0,
    };


    // Alice generates a public key
    kyberRefKeyPair(  publicKeyCuda, secretKeyCuda, keyPairCoins);
    kyberCudaKeyPair( publicKeyRef,  secretKeyRef,  keyPairCoins);

    if ( memcmp( publicKeyRef, publicKeyCuda, kyberPublicKeyBytes) ) 
    {
        printf("Public Keys dismatch\n");
        return 1;
    }

    if ( memcmp( secretKeyRef, secretKeyCuda, kyberSecretKeyBytes) ) 
    {
        printf("Secret Keys dismatch\n");
        return 2;
    }

    return 0;
}

int main()
{
    assert( testKeygen() == 0 );
}

