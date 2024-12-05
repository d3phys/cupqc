#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <chrono>
#include <iostream>

#include "test-api.hh"

extern "C"
{
//#include "../../ref/kyber/ref/api.h"
#include "../../ref/kyber/avx2/api.h"

void randombytes(uint8_t *out, size_t outlen) {}
}

int pqcrystals_kyber512_cuda_keypair(uint8_t *pk, uint8_t *sk, uint32_t keypair_count);

int kyberCudaKeyPairs( uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count)
{
    // Coins are the same
    uint32_t step = 128 * 4;

    for ( uint32_t i = 0; i < (keypair_count / step); ++i )
    {
        uint8_t* pub = (pk + kyberPublicKeyBytes * i * step);
        uint8_t* sec = (sk + kyberSecretKeyBytes * i * step);
        pqcrystals_kyber512_cuda_keypair( pub, sec, step);
    }

    return 0;
}

//int kyberRefKeyPairs( uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count)
//{
//    for ( uint32_t i = 0; i < keypair_count; ++i )
//    {
//        uint8_t* pub = (pk + kyberPublicKeyBytes * i);
//        uint8_t* sec = (sk + kyberSecretKeyBytes * i);
//        pqcrystals_kyber512_ref_keypair_derand( pub, sec, coins);
//    }
//
//    return 0;
//}

int kyberRefKeyPairs( uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count)
{
    for ( uint32_t i = 0; i < keypair_count; ++i )
    {
        uint8_t* pub = (pk + kyberPublicKeyBytes * i);
        uint8_t* sec = (sk + kyberSecretKeyBytes * i);
        pqcrystals_kyber512_avx2_keypair_derand( pub, sec, coins);
    }

    return 0;
}

const uint32_t nKeys = 128 * 1000;

int testKeygen()
{
    uint8_t* publicKeysRef = (uint8_t*)malloc( kyberPublicKeyBytes * nKeys);
    uint8_t* secretKeysRef = (uint8_t*)malloc( kyberSecretKeyBytes * nKeys);

    uint8_t* publicKeysCuda = (uint8_t*)malloc( kyberPublicKeyBytes * nKeys);
    uint8_t* secretKeysCuda = (uint8_t*)malloc( kyberSecretKeyBytes * nKeys);

    uint8_t keyPairCoins[kyberKeyPairCoinBytes] = {
        0xcb, 0x12, 0x61, 0xa8, 0xcf, 0x85, 0xa4, 0x8b, 0x5d, 0x37, 0xc1, 0x00, 0xb6, 0xb0, 0x2c, 0xfb,
        0x1b, 0x84, 0x78, 0xc6, 0x2f, 0xe1, 0xc7, 0xd0, 0xe2, 0xcc, 0x0b, 0x48, 0xe7, 0xb7, 0xae, 0xfd,
        0x7f, 0xe1, 0xa8, 0x95, 0xdb, 0xd9, 0x28, 0x88, 0x12, 0xf2, 0x68, 0xc0, 0x84, 0x8e, 0xe0, 0xa6,
        0x1f, 0xe5, 0xd3, 0x21, 0xbb, 0xcf, 0x6d, 0x3c, 0x98, 0xb5, 0x35, 0xc4, 0x74, 0xae, 0x1a, 0xb0,
    };

    // Alice generates a public key
    auto startRef = std::chrono::high_resolution_clock::now();
    kyberRefKeyPairs(  publicKeysRef, secretKeysRef, keyPairCoins, nKeys);
    auto endRef   = std::chrono::high_resolution_clock::now();

    auto startCuda = std::chrono::high_resolution_clock::now();
    kyberCudaKeyPairs( publicKeysCuda, secretKeysCuda, keyPairCoins, nKeys);
    auto endCuda = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> diffRef = endRef - startRef;
    std::chrono::duration<double> diffCuda = endCuda - startCuda;

    std::cout << "Ref. time: " << diffRef.count() << "s\n";
    std::cout << "Cuda time: " << diffCuda.count() << "s\n";

    if ( memcmp( publicKeysRef, publicKeysCuda, nKeys * kyberPublicKeyBytes) ) 
    {
        printf("Public Keys dismatch\n");
        return 1;
    }

    if ( memcmp( secretKeysRef, secretKeysCuda, nKeys * kyberSecretKeyBytes) ) 
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

