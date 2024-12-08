#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "params.h"

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#endif

#define crypto_kem_keypair_kernel KYBER_NAMESPACE(keypair_kernel)
__global__ void crypto_kem_keypair_kernel(uint8_t *pk, uint8_t *sk, const uint8_t *coins, uint32_t n_keypair);

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk, uint32_t n_keypair);

#define crypto_kem_enc_kernel KYBER_NAMESPACE(enc_kernel)
__global__ void crypto_kem_enc_kernel(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, uint32_t n_keypair);

#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, uint32_t n_keypair);

#define crypto_kem_dec_kernel KYBER_NAMESPACE(dec_kernel)
__global__ void crypto_kem_dec_kernel(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint32_t n_keypair);

#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, uint32_t n_keypair);

#endif
