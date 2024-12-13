#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <functional>
#include <vector>

#include "test-api.hh"

extern "C"
{

#include "../../ref/kyber/ref/api.h"
#include "../../ref/kyber/avx2/api.h"

void randombytes(uint8_t *out, size_t outlen) {}
}

int pqcrystals_init();
int pqcrystals_kyber768_cuda_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count);
int pqcrystals_kyber768_cuda_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, uint32_t keypair_count);
int pqcrystals_kyber768_cuda_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint32_t keypair_count);

using KyberKeyPair = int( uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count);
using KyberEnc = int( uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, uint32_t keypair_count);
using KyberDec = int( uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint32_t keypair_count);

int kyberCudaInit()
{
    return pqcrystals_init();
}

int kyberCudaKeyPair( uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count)
{
    pqcrystals_kyber768_cuda_keypair( pk, sk, coins, keypair_count);
    return 0;
}

int kyberAvx2KeyPair( uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count)
{
    for ( uint32_t i = 0; i < keypair_count; ++i )
    {
        uint8_t* pub = (pk + kyberPublicKeyBytes * i);
        uint8_t* sec = (sk + kyberSecretKeyBytes * i);
        const uint8_t* cns = (coins + kyberKeyPairCoinBytes * i);
        pqcrystals_kyber768_avx2_keypair_derand( pub, sec, cns);
    }

    return 0;
}

int kyberRefKeyPair( uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t keypair_count)
{
    for ( uint32_t i = 0; i < keypair_count; ++i )
    {
        uint8_t* pub = (pk + kyberPublicKeyBytes * i);
        uint8_t* sec = (sk + kyberSecretKeyBytes * i);
        const uint8_t* cns = (coins + kyberKeyPairCoinBytes * i);
        pqcrystals_kyber768_ref_keypair_derand( pub, sec, cns);
    }

    return 0;
}

int kyberCudaEnc( uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, uint32_t keypair_count)
{
    pqcrystals_kyber768_cuda_enc( ct, ss, pk, coins, keypair_count);
    return 0;
}

int kyberAvx2Enc( uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, uint32_t keypair_count)
{
    for ( uint32_t i = 0; i < keypair_count; ++i )
    {
        uint8_t* cph = (ct + kyberCipherTextBytes * i);
        uint8_t* shr = (ss + kyberBytes * i);
        const uint8_t* pub = (pk + kyberPublicKeyBytes * i);
        const uint8_t* cns = (coins + kyberEncCoinBytes * i);
        pqcrystals_kyber768_avx2_enc_derand( cph, shr, pub, cns);
    }

    return 0;
}

int kyberRefEnc( uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, uint32_t keypair_count)
{
    for ( uint32_t i = 0; i < keypair_count; ++i )
    {
        uint8_t* cph = (ct + kyberCipherTextBytes * i);
        uint8_t* shr = (ss + kyberBytes * i);
        const uint8_t* pub = (pk + kyberPublicKeyBytes * i);
        const uint8_t* cns = (coins + kyberEncCoinBytes * i);
        pqcrystals_kyber768_ref_enc_derand( cph, shr, pub, cns);
    }

    return 0;
}

int kyberCudaDec( uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint32_t keypair_count)
{
    pqcrystals_kyber768_cuda_dec( ss, ct, sk, keypair_count);
    return 0;
}

int kyberAvx2Dec( uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint32_t keypair_count)
{
    for ( uint32_t i = 0; i < keypair_count; ++i )
    {
        uint8_t* shr = (ss + kyberBytes * i);
        const uint8_t* cph = (ct + kyberCipherTextBytes * i);
        const uint8_t* sec = (sk + kyberSecretKeyBytes * i);
        pqcrystals_kyber768_avx2_dec( shr, cph, sec);
    }

    return 0;
}

int kyberRefDec( uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint32_t keypair_count)
{
    for ( uint32_t i = 0; i < keypair_count; ++i )
    {
        uint8_t* shr = (ss + kyberBytes * i);
        const uint8_t* cph = (ct + kyberCipherTextBytes * i);
        const uint8_t* sec = (sk + kyberSecretKeyBytes * i);
        pqcrystals_kyber768_ref_dec( shr, cph, sec);
    }

    return 0;
}

std::unique_ptr<uint8_t[]> createCoins(const int nCoins, int coinBytes)
{
    assert(coinBytes <= kyberKeyPairCoinBytes);

    uint8_t keyPairCoins[kyberKeyPairCoinBytes] = {
        0xcb, 0x12, 0x61, 0xa8, 0xcf, 0x85, 0xa4, 0x8b, 0x5d, 0x37, 0xc1, 0x00, 0xb6, 0xb0, 0x2c, 0xfb,
        0x1b, 0x84, 0x78, 0xc6, 0x2f, 0xe1, 0xc7, 0xd0, 0xe2, 0xcc, 0x0b, 0x48, 0xe7, 0xb7, 0xae, 0xfd,
        0x7f, 0xe1, 0xa8, 0x95, 0xdb, 0xd9, 0x28, 0x88, 0x12, 0xf2, 0x68, 0xc0, 0x84, 0x8e, 0xe0, 0xa6,
        0x1f, 0xe5, 0xd3, 0x21, 0xbb, 0xcf, 0x6d, 0x3c, 0x98, 0xb5, 0x35, 0xc4, 0x74, 0xae, 0x1a, 0xb0,
    };
    
    std::unique_ptr<uint8_t[]> coins = std::make_unique<uint8_t[]>(coinBytes * nCoins);

    for ( int i = 0; i < nCoins; i++ )
    {
        memcpy(coins.get() + i * coinBytes, keyPairCoins, coinBytes);
    }

    return coins;
}

std::pair<std::unique_ptr<uint8_t[]>, std::unique_ptr<uint8_t[]>>
runKyberKeyPair(int nKeys, KyberKeyPair kyberKeyPair, double* duration = nullptr) {
    auto publicKeys = std::make_unique<uint8_t[]>( kyberPublicKeyBytes * nKeys);
    auto secretKeys = std::make_unique<uint8_t[]>( kyberSecretKeyBytes * nKeys);
    auto coins = createCoins(nKeys, kyberKeyPairCoinBytes);

    auto startRef = std::chrono::high_resolution_clock::now();
    kyberKeyPair( publicKeys.get(), secretKeys.get(), coins.get(), nKeys);
    auto endRef   = std::chrono::high_resolution_clock::now();

    if ( duration ) 
    {
        std::chrono::duration<double> diff = endRef - startRef;
        *duration = diff.count();
    }

    return {std::move(publicKeys), std::move(secretKeys)};
}

std::pair<std::unique_ptr<uint8_t[]>, std::unique_ptr<uint8_t[]>>
runKyberEnc(const uint8_t* publicKeys, int nKeys, KyberEnc kyberEnc, double* duration = nullptr) {
    auto cipherTexts = std::make_unique<uint8_t[]>( kyberCipherTextBytes * nKeys);
    auto sharedSecrets = std::make_unique<uint8_t[]>( kyberBytes * nKeys);
    auto coins = createCoins(nKeys, kyberEncCoinBytes);

    auto startRef = std::chrono::high_resolution_clock::now();
    kyberEnc( cipherTexts.get(), sharedSecrets.get(), publicKeys, coins.get(), nKeys);
    auto endRef   = std::chrono::high_resolution_clock::now();

    if ( duration ) 
    {
        std::chrono::duration<double> diff = endRef - startRef;
        *duration = diff.count();
    }

    return {std::move(cipherTexts), std::move(sharedSecrets)};
}

std::unique_ptr<uint8_t[]>
runKyberDec(const uint8_t* cipherTexts, const uint8_t* secretKeys, int nKeys, KyberDec kyberDec, double* duration = nullptr) {
    auto sharedSecrets = std::make_unique<uint8_t[]>( kyberBytes * nKeys);

    auto startRef = std::chrono::high_resolution_clock::now();
    kyberDec( sharedSecrets.get(), cipherTexts, secretKeys, nKeys);
    auto endRef   = std::chrono::high_resolution_clock::now();

    if ( duration ) 
    {
        std::chrono::duration<double> diff = endRef - startRef;
        *duration = diff.count();
    }

    return sharedSecrets;
}

int testKeygen(int nKeys)
{
    double durRef = 0;
    double durAvx2 = 0;
    double durCuda = 0;

    auto [publicKeysRef, secretKeysRef] = runKyberKeyPair(nKeys, kyberRefKeyPair, &durRef);
    auto [publicKeysAvx2, secretKeysAvx2] = runKyberKeyPair(nKeys, kyberAvx2KeyPair, &durAvx2);
    auto [publicKeysCuda, secretKeysCuda] = runKyberKeyPair(nKeys, kyberCudaKeyPair, &durCuda);

    std::cout << "Ref. time: " << durRef  << "s\n";
    std::cout << "Avx2 time: " << durAvx2 << "s\n";
    std::cout << "Cuda time: " << durCuda << "s\n";

    if ( memcmp( publicKeysRef.get(), publicKeysCuda.get(), nKeys * kyberPublicKeyBytes) ) 
    {
        std::cerr << "Public Keys mismatch\n";
        return 1;
    }

    if ( memcmp( secretKeysRef.get(), secretKeysCuda.get(), nKeys * kyberSecretKeyBytes) ) 
    {
        std::cerr << "Secret Keys mismatch\n";
        return 2;
    }

    return 0;
}

int testEnc(int nKeys) {
    double durRef = 0;
    double durAvx2 = 0;
    double durCuda = 0;

    auto [publicKeysCuda, _] = runKyberKeyPair(nKeys, kyberRefKeyPair);

    auto [cipherTextsRef, sharedSecretsRef]   = runKyberEnc( publicKeysCuda.get(), nKeys, kyberRefEnc, &durRef);
    auto [cipherTextsAvx2, sharedSecretsAvx2] = runKyberEnc( publicKeysCuda.get(), nKeys, kyberAvx2Enc, &durAvx2);
    auto [cipherTextsCuda, sharedSecretsCuda] = runKyberEnc( publicKeysCuda.get(), nKeys, kyberCudaEnc, &durCuda);

    std::cout << "Ref. time: " << durRef  << "s\n";
    std::cout << "Avx2 time: " << durAvx2 << "s\n";
    std::cout << "Cuda time: " << durCuda << "s\n";

    if ( memcmp( cipherTextsRef.get(), cipherTextsCuda.get(), nKeys * kyberCipherTextBytes) ) 
    {
        std::cerr << "Cipher Texts mismatch\n";
        return 1;
    }

    if ( memcmp( sharedSecretsRef.get(), sharedSecretsCuda.get(), nKeys * kyberBytes) ) 
    {
        std::cerr << "Shared Secrets mismatch\n";
        return 2;
    }

    return 0;
}

int testDec(int nKeys) {
    double durRef = 0;
    double durAvx2 = 0;
    double durCuda = 0;

    auto [publicKeysCuda, secretKeysCuda] = runKyberKeyPair(nKeys, kyberRefKeyPair);
    auto [cipherTextsCuda, _] = runKyberEnc( publicKeysCuda.get(), nKeys, kyberRefEnc);

    auto sharedSecretsRef  = runKyberDec( cipherTextsCuda.get(), secretKeysCuda.get(), nKeys, kyberRefDec,  &durRef);
    auto sharedSecretsAvx2 = runKyberDec( cipherTextsCuda.get(), secretKeysCuda.get(), nKeys, kyberAvx2Dec, &durAvx2);
    auto sharedSecretsCuda = runKyberDec( cipherTextsCuda.get(), secretKeysCuda.get(), nKeys, kyberCudaDec, &durCuda);

    std::cout << "Ref. time: " << durRef  << "s\n";
    std::cout << "Avx2 time: " << durAvx2 << "s\n";
    std::cout << "Cuda time: " << durCuda << "s\n";

    if ( memcmp( sharedSecretsRef.get(), sharedSecretsCuda.get(), nKeys * kyberBytes) ) 
    {
        std::cerr << "Shared Secrets mismatch\n";
        return 1;
    }

    return 0;
}

int main(int argc, const char *argv[])
{
    const uint32_t kDefaultNKeys = 128 * 1000;
    const std::vector<std::function<int(int)>> kDefaultTests = {testKeygen, testEnc, testDec};

    uint32_t nKeys = kDefaultNKeys;
    std::vector<std::function<int(int)>> tests = kDefaultTests;

    if ( argc > 1 )
    {
        nKeys = std::atoi(argv[1]);

        if ( argc > 2 )
        {
            std::string testName = argv[2];
            tests.clear();

            if ( testName == "all" )
            {
                tests = kDefaultTests;
            } else if ( testName == "keygen" )
            {
                tests.push_back(testKeygen);
            } else if ( testName == "enc" )
            {
                tests.push_back(testEnc);
            } else if ( testName == "dec" )
            {
                tests.push_back(testDec);
            } else
            {
                std::cerr << "Unknown test " << testName;
                assert(0);
            }
        }
    }

    kyberCudaInit();
    for ( auto &&test : tests )
    {
        int result = test(nKeys);
        assert(result == 0);
    }

    return 0;
}

