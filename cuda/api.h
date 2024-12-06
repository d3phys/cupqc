#ifndef API_H
#define API_H

#include <stdint.h>
#include "params.h"

constexpr int kyber512SecretKeyBytes   = 1632;
constexpr int kyber512PublicKeyBytes   = 800;
constexpr int kyber512CipherTextBytes  = 768;
constexpr int kyber512KeyPairCoinBytes = 64;
constexpr int kyber512EncCoinBytes     = 32;
constexpr int kyber512Bytes            = 32;

int pqcrystals_kyber512_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber512_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcrystals_kyber512_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

constexpr int kyber768SecretKeyBytes   = 2400;
constexpr int kyber768PublicKeyBytes   = 1184;
constexpr int kyber768CipherTextBytes  = 1088;
constexpr int kyber768KeyPairCoinBytes = 64;
constexpr int kyber768EncCoinBytes     = 32;
constexpr int kyber768Bytes            = 32;

int pqcrystals_kyber768_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber768_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

constexpr int kyber1024SecretKeyBytes   = 3168;
constexpr int kyber1024PublicKeyBytes   = 1568;
constexpr int kyber1024CipherTextBytes  = 1568;
constexpr int kyber1024KeyPairCoinBytes = 64;
constexpr int kyber1024EncCoinBytes     = 32;
constexpr int kyber1024Bytes            = 32;

int pqcrystals_kyber1024_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber1024_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if (KYBER_K == 2)

#define kyberSecretKeyBytes   kyber512SecretKeyBytes
#define kyberPublicKeyBytes   kyber512PublicKeyBytes
#define kyberCipherTextBytes  kyber512CipherTextBytes
#define kyberKeyPairCoinBytes kyber512KeyPairCoinBytes
#define kyberEncCoinBytes     kyber512EncCoinBytes
#define kyberBytes            kyber512Bytes           

#define kyberKeyPair          kyber512KeyPair
#define kyberKeyPairDeRand    kyber512KeyPairDeRand
#define kyberKeyPair          kyber512KeyPair
#define kyberEncDeRand        kyber512EncDeRand
#define kyberEnc              kyber512Enc
#define kyberDec              kyber512Dec

#elif (KYBER_K == 3)

#define kyberSecretKeyBytes   kyber768SecretKeyBytes
#define kyberPublicKeyBytes   kyber768PublicKeyBytes
#define kyberCipherTextBytes  kyber768CipherTextBytes
#define kyberKeyPairCoinBytes kyber768KeyPairCoinBytes
#define kyberEncCoinBytes     kyber768EncCoinBytes
#define kyberBytes            kyber768Bytes           

#define kyberKeyPair          kyber768KeyPair
#define kyberKeyPairDeRand    kyber768KeyPairDeRand
#define kyberKeyPair          kyber768KeyPair
#define kyberEncDeRand        kyber768EncDeRand
#define kyberEnc              kyber768Enc
#define kyberDec              kyber768Dec

#elif (KYBER_K == 4)

#define kyberSecretKeyBytes   kyber1024SecretKeyBytes
#define kyberPublicKeyBytes   kyber1024PublicKeyBytes
#define kyberCipherTextBytes  kyber1024CipherTextBytes
#define kyberKeyPairCoinBytes kyber1024KeyPairCoinBytes
#define kyberEncCoinBytes     kyber1024EncCoinBytes
#define kyberBytes            kyber1024Bytes           

#define kyberKeyPair          kyber1024KeyPair
#define kyberKeyPairDeRand    kyber1024KeyPairDeRand
#define kyberKeyPair          kyber1024KeyPair
#define kyberEncDeRand        kyber1024EncDeRand
#define kyberEnc              kyber1024Enc
#define kyberDec              kyber1024Dec

#else
#error "Unknown KYBER_K"
#endif

#endif
