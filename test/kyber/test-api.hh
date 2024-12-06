#ifndef KYBER_TEST_API_H
#define KYBER_TEST_API_H

#include <stdint.h>

constexpr int kyber512SecretKeyBytes   = 1632;
constexpr int kyber512PublicKeyBytes   = 800;
constexpr int kyber512CipherTextBytes  = 768;
constexpr int kyber512KeyPairCoinBytes = 64;
constexpr int kyber512EncCoinBytes     = 32;
constexpr int kyber512Bytes            = 32;

int kyber512KeyPair(uint8_t *pk, uint8_t *sk);
int kyber512KeyPairDeRand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int kyber512KeyPair(uint8_t *pk, uint8_t *sk);
int kyber512EncDeRand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int kyber512Enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kyber512Dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

constexpr int kyber768SecretKeyBytes   = 2400;
constexpr int kyber768PublicKeyBytes   = 1184;
constexpr int kyber768CipherTextBytes  = 1088;
constexpr int kyber768KeyPairCoinBytes = 64;
constexpr int kyber768EncCoinBytes     = 32;
constexpr int kyber768Bytes            = 32;

int kyber768KeyPair(uint8_t *pk, uint8_t *sk);
int kyber768KeyPairDeRand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int kyber768KeyPair(uint8_t *pk, uint8_t *sk);
int kyber768EncDeRand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int kyber768Enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kyber768Dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

constexpr int kyber1024SecretKeyBytes   = 3168;
constexpr int kyber1024PublicKeyBytes   = 1568;
constexpr int kyber1024CipherTextBytes  = 1568;
constexpr int kyber1024KeyPairCoinBytes = 64;
constexpr int kyber1024EncCoinBytes     = 32;
constexpr int kyber1024Bytes            = 32;

int kyber1024KeyPair(uint8_t *pk, uint8_t *sk);
int kyber1024KeyPairDeRand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int kyber1024KeyPair(uint8_t *pk, uint8_t *sk);
int kyber1024EncDeRand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int kyber1024Enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kyber1024Dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Test Kyber768 for now
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

#endif // KYBER_TEST_API_H
