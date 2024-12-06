#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

#include <cuda.h>

#define GPU_ASSERT(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true)
{
   if (code != cudaSuccess)
   {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}

/*************************************************
* Name:        crypto_kem_keypair_derand
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes per thread)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes per thread)
*              - uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with 2*KYBER_SYMBYTES random bytes per thread)
**
* Returns 0 (success)
**************************************************/
__global__ void
crypto_kem_keypair_derand(uint8_t *pk,
                          uint8_t *sk,
                          const uint8_t *coins,
                          uint32_t keypair_count)
{
  const int tid = threadIdx.x;
  const int block_size = blockDim.x;
  const int bid = blockIdx.x;
  const int coins_offset = ( bid * block_size + tid ) * 2 * KYBER_SYMBYTES;
  const int sk_offset = ( bid * block_size + tid ) * KYBER_SECRETKEYBYTES;
  const int pk_offset = ( bid * block_size + tid ) * KYBER_PUBLICKEYBYTES;

  if ( bid * block_size + tid < keypair_count )
  {
    indcpa_keypair_derand(pk + pk_offset, sk + sk_offset, coins + coins_offset);
    memcpy(sk + sk_offset + KYBER_INDCPA_SECRETKEYBYTES, pk + pk_offset, KYBER_PUBLICKEYBYTES);
    hash_h(sk + sk_offset + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk + pk_offset, KYBER_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(sk + sk_offset + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, coins + coins_offset + KYBER_SYMBYTES, KYBER_SYMBYTES);
  }
}

#define MAX_BLOCK_SIZE 128

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk,
                       const uint8_t *coins,
                       uint32_t keypair_count)
{
  dim3 block_dim (1, 1, 1);
  dim3 grid_dim (1, 1, 1);

  if (keypair_count <= MAX_BLOCK_SIZE) {
    block_dim.x = keypair_count;
    grid_dim.x = 1;
  } else {
    block_dim.x = MAX_BLOCK_SIZE;
    grid_dim.x = ( keypair_count + MAX_BLOCK_SIZE - 1 ) / MAX_BLOCK_SIZE;
  }

  uint8_t *d_pk = nullptr;
  uint8_t *d_sk = nullptr;
  uint8_t *d_coins = nullptr;

  cudaMalloc( &d_pk, keypair_count * CRYPTO_PUBLICKEYBYTES);
  cudaMalloc( &d_sk, keypair_count * CRYPTO_SECRETKEYBYTES);
  cudaMalloc( &d_coins, keypair_count * 2 * KYBER_SYMBYTES);
  assert( d_pk && d_sk && d_coins);

  GPU_ASSERT( cudaMemcpy( d_coins, coins, keypair_count * 2 * KYBER_SYMBYTES, cudaMemcpyHostToDevice) );

  printf( "gridDim (%d %d %d), blockDim (%d %d %d)\n", grid_dim.x, grid_dim.y, grid_dim.z, block_dim.x, block_dim.y, block_dim.z);
  crypto_kem_keypair_derand<<<grid_dim, block_dim>>>( d_pk, d_sk, d_coins, keypair_count);

  GPU_ASSERT( cudaGetLastError() );

  GPU_ASSERT( cudaMemcpy( pk, d_pk, keypair_count * CRYPTO_PUBLICKEYBYTES, cudaMemcpyDeviceToHost) );
  GPU_ASSERT( cudaMemcpy( sk, d_sk, keypair_count * CRYPTO_SECRETKEYBYTES, cudaMemcpyDeviceToHost) );
  cudaFree( d_pk);
  cudaFree( d_sk);
  cudaFree( d_coins);
  return 0;
}

#if 0
/*************************************************
* Name:        crypto_kem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with KYBER_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/
__device__ void
crypto_kem_enc_derand(uint8_t *ct,
                      uint8_t *ss,
                      const uint8_t *pk,
                      const uint8_t *coins,
                      uint32_t keypair_count)
{
  const int tid = threadIdx.x;
  const int block_size = blockDim.x;
  const int bid = blockIdx.x;
  const int coins_offset = ( bid * block_size + tid ) * 2 * KYBER_SYMBYTES;
  const int sk_offset = ( bid * block_size + tid ) * KYBER_SECRETKEYBYTES;
  const int pk_offset = ( bid * block_size + tid ) * KYBER_PUBLICKEYBYTES;

  if ( bid * block_size + tid < keypair_count )
  {
      uint8_t buf[2*KYBER_SYMBYTES];
      /* Will contain key, coins */
      uint8_t kr[2*KYBER_SYMBYTES];

      memcpy(buf, coins, KYBER_SYMBYTES);

      /* Multitarget countermeasure for coins + contributory KEM */
      hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
      hash_g(kr, buf, 2*KYBER_SYMBYTES);

      /* coins are in kr+KYBER_SYMBYTES */
      indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

      memcpy(ss,kr,KYBER_SYMBYTES);
  }
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t coins[KYBER_SYMBYTES];
  randombytes(coins, KYBER_SYMBYTES);
  crypto_kem_enc_derand(ct, ss, pk, coins);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  memcpy(buf+KYBER_SYMBYTES, sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, KYBER_SYMBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* Compute rejection key */
  rkprf(ss,sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES,ct);

  /* Copy true key to return buffer if fail is false */
  cmov(ss,kr,KYBER_SYMBYTES,!fail);

  return 0;
}
#endif
