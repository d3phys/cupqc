#include "../test-api.hh"
#include <stdlib.h>

#include "../../../cuda/api.h"

// Stub for dynamic library
//extern "C"
//void randombytes(uint8_t *out, size_t outlen) {}
//
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk, uint32_t keypair_count);

int kyber512KeyPairDeRand(uint8_t *pk, uint8_t *sk, const uint8_t* coins)
{
    return pqcrystals_kyber512_cuda_keypair_derand( pk, sk, coins, 1);

    return pqcrystals_kyber512_ref_keypair_derand

}


int kyber512EncDeRand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t* coins)
{
    return pqcrystals_kyber512_ref_enc_derand( ct, ss, pk, coins);
}

int kyber512Dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    return pqcrystals_kyber512_ref_dec( ss, ct, sk);
}
