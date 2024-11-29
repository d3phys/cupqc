#include "../../test-api.hh"
#include <stdlib.h>

extern "C"
{
#include "../../../../ref/kyber/avx2/api.h"
}

// Stub for dynamic library
extern "C"
void randombytes(uint8_t *out, size_t outlen) {}

int kyber512KeyPairDeRand(uint8_t *pk, uint8_t *sk, const uint8_t* coins)
{
    return pqcrystals_kyber512_avx2_keypair_derand( pk, sk, coins);
}

int kyber512EncDeRand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t* coins)
{
    return pqcrystals_kyber512_avx2_enc_derand( ct, ss, pk, coins);
}

int kyber512Dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return pqcrystals_kyber512_avx2_dec( ss, ct, sk);
}

int kyber768KeyPairDeRand(uint8_t *pk, uint8_t *sk, const uint8_t* coins)
{
    return pqcrystals_kyber768_avx2_keypair_derand( pk, sk, coins);
}

int kyber768EncDeRand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t* coins)
{
    return pqcrystals_kyber768_avx2_enc_derand( ct, ss, pk, coins);
}

int kyber768Dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return pqcrystals_kyber768_avx2_dec( ss, ct, sk);
}
