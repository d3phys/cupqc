#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <vector>
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
* Name:        crypto_kem_keypair_kernel
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
*              - uint32_t n_keypair: amount of keys to generate
*
* Returns 0 (success)
**************************************************/
__global__ void
crypto_kem_keypair_kernel(uint8_t *pk,
                          uint8_t *sk,
                          const uint8_t *coins,
                          uint32_t n_keypair)
{
  const int tid = threadIdx.x;
  const int block_size = blockDim.x;
  const int bid = blockIdx.x;

  const int idx = bid * block_size + tid;
  uint8_t       *thread_pk    = pk    + idx * KYBER_PUBLICKEYBYTES;
  uint8_t       *thread_sk    = sk    + idx * KYBER_SECRETKEYBYTES;
  const uint8_t *thread_coins = coins + idx * 2*KYBER_SYMBYTES;

  if ( idx < n_keypair )
  {
    indcpa_keypair_derand(thread_pk, thread_sk, thread_coins);
    memcpy(thread_sk + KYBER_INDCPA_SECRETKEYBYTES, thread_pk, KYBER_PUBLICKEYBYTES);
    hash_h(thread_sk + KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES, thread_pk, KYBER_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(thread_sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, thread_coins + KYBER_SYMBYTES, KYBER_SYMBYTES);
  }
}

#define MAX_BLOCK_SIZE 128
const uint32_t kThreadsPerBlock = 32;
const uint32_t kBlocksPerGrid = 256;
const uint32_t kKeysPerGrid = kBlocksPerGrid * kThreadsPerBlock;

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
                       uint32_t n_keypair)
{
  const uint32_t n_streams = (n_keypair + kKeysPerGrid - 1) / kKeysPerGrid;
  const uint32_t tail_keypairs = n_keypair % kKeysPerGrid;

  uint8_t *d_pk = nullptr;
  uint8_t *d_sk = nullptr;
  uint8_t *d_coins = nullptr;

  cudaMalloc( &d_pk, n_keypair * KYBER_PUBLICKEYBYTES);
  cudaMalloc( &d_sk, n_keypair * KYBER_SECRETKEYBYTES);
  cudaMalloc( &d_coins, n_keypair * 2 * KYBER_SYMBYTES);
  assert( d_pk && d_sk && d_coins);

  GPU_ASSERT( cudaMemcpy( d_coins, coins, n_keypair * 2 * KYBER_SYMBYTES, cudaMemcpyHostToDevice) );

  std::vector<cudaStream_t> streams( n_streams);
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    GPU_ASSERT( cudaStreamCreate( &streams[i]));
  }

  auto getNKeysForGrid = [=]( uint32_t i) -> uint32_t
  {
    if ( (tail_keypairs != 0) && (i == n_streams - 1) )
    {
      return tail_keypairs;
    } else {
      return kKeysPerGrid;
    }
  };

  // Launch all grids in streams.
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    uint32_t offset = i * kKeysPerGrid;
    uint32_t n_cur = getNKeysForGrid( i);

    uint8_t *d_grid_pk    = d_pk    + offset * KYBER_PUBLICKEYBYTES;
    uint8_t *d_grid_sk    = d_sk    + offset * KYBER_SECRETKEYBYTES;
    uint8_t *d_grid_coins = d_coins + offset * 2*KYBER_SYMBYTES;

    printf( "keygen gridDim (%u), blockDim (%u), stream launch (%u), #keypairs on grid (%u keys), offset (%u keys)\n",
            kBlocksPerGrid, kThreadsPerBlock, i, n_cur, offset);
    crypto_kem_keypair_kernel<<<kBlocksPerGrid, kThreadsPerBlock, 0, streams[i]>>>(
        d_grid_pk,
        d_grid_sk,
        d_grid_coins,
        n_cur
    );
  }

  // Launch copy for result of every stream.
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    uint32_t offset = i * kKeysPerGrid;
    uint32_t n_cur = getNKeysForGrid( i);

    uint8_t *h_grid_pk = pk   + offset * KYBER_PUBLICKEYBYTES;
    uint8_t *h_grid_sk = sk   + offset * KYBER_SECRETKEYBYTES;
    uint8_t *d_grid_pk = d_pk + offset * KYBER_PUBLICKEYBYTES;
    uint8_t *d_grid_sk = d_sk + offset * KYBER_SECRETKEYBYTES;

    GPU_ASSERT( cudaMemcpyAsync( h_grid_pk,
                                 d_grid_pk,
                                 n_cur * KYBER_PUBLICKEYBYTES,
                                 cudaMemcpyDeviceToHost,
                                 streams[i]));

    GPU_ASSERT( cudaMemcpyAsync( h_grid_sk,
                                 d_grid_sk,
                                 n_cur * KYBER_SECRETKEYBYTES,
                                 cudaMemcpyDeviceToHost,
                                 streams[i]));
  }

  // Wait for all streams.
  GPU_ASSERT( cudaDeviceSynchronize());

  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    GPU_ASSERT( cudaStreamDestroy( streams[i]));
  }

  cudaFree( d_pk);
  cudaFree( d_sk);
  cudaFree( d_coins);

  return 0;
}

/*************************************************
* Name:        crypto_kem_enc_kernel
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
__global__ void
crypto_kem_enc_kernel(uint8_t *ct,
                      uint8_t *ss,
                      const uint8_t *pk,
                      const uint8_t *coins,
                      uint32_t n_keypair)
{
  const int tid = threadIdx.x;
  const int block_size = blockDim.x;
  const int bid = blockIdx.x;
  const int coins_offset = ( bid * block_size + tid ) * KYBER_SYMBYTES;
  const int pk_offset = ( bid * block_size + tid ) * KYBER_PUBLICKEYBYTES;
  const int ct_offset = ( bid * block_size + tid ) * KYBER_INDCPA_BYTES;
  const int ss_offset = ( bid * block_size + tid ) * KYBER_SSBYTES;

  if ( bid * block_size + tid < n_keypair )
  {
      uint8_t buf[2*KYBER_SYMBYTES];
      /* Will contain key, coins */
      uint8_t kr[2*KYBER_SYMBYTES];

      memcpy(buf, coins + coins_offset, KYBER_SYMBYTES);

      /* Multitarget countermeasure for coins + contributory KEM */
      hash_h(buf + KYBER_SYMBYTES, pk + pk_offset, KYBER_PUBLICKEYBYTES);
      hash_g(kr, buf, 2*KYBER_SYMBYTES);

      /* coins are in kr+KYBER_SYMBYTES */
      indcpa_enc(ct + ct_offset, buf, pk + pk_offset, kr + KYBER_SYMBYTES);

      memcpy(ss + ss_offset,kr,KYBER_SYMBYTES);
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
                   const uint8_t *pk,
                   const uint8_t *coins,
                   uint32_t n_keypair)
{
  const uint32_t n_streams = (n_keypair + kKeysPerGrid - 1) / kKeysPerGrid;
  const uint32_t tail_keypairs = n_keypair % kKeysPerGrid;

  uint8_t *d_ct = nullptr;
  uint8_t *d_ss = nullptr;
  uint8_t *d_pk = nullptr;
  uint8_t *d_coins = nullptr;

  cudaMalloc( &d_ct, n_keypair * KYBER_CIPHERTEXTBYTES);
  cudaMalloc( &d_ss, n_keypair * KYBER_SSBYTES);
  cudaMalloc( &d_pk, n_keypair * KYBER_PUBLICKEYBYTES);
  cudaMalloc( &d_coins, n_keypair * KYBER_SYMBYTES);
  assert( d_ct && d_ss && d_pk && d_coins);

  GPU_ASSERT( cudaMemcpy( d_pk, pk, n_keypair * KYBER_PUBLICKEYBYTES, cudaMemcpyHostToDevice) );
  GPU_ASSERT( cudaMemcpy( d_coins, coins, n_keypair * KYBER_SYMBYTES, cudaMemcpyHostToDevice) );

  std::vector<cudaStream_t> streams( n_streams);
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    GPU_ASSERT( cudaStreamCreate( &streams[i]));
  }

  auto getNKeysForGrid = [=]( uint32_t i) -> uint32_t
  {
    if ( (tail_keypairs != 0) && (i == n_streams - 1) )
    {
      return tail_keypairs;
    } else {
      return kKeysPerGrid;
    }
  };

  // Launch all grids in streams.
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    uint32_t offset = i * kKeysPerGrid;
    uint32_t n_cur = getNKeysForGrid( i);

    uint8_t *d_grid_ct    = d_ct    + offset * KYBER_CIPHERTEXTBYTES;
    uint8_t *d_grid_ss    = d_ss    + offset * KYBER_SSBYTES;
    uint8_t *d_grid_pk    = d_pk    + offset * KYBER_PUBLICKEYBYTES;
    uint8_t *d_grid_coins = d_coins + offset * KYBER_SYMBYTES;

    printf( "enc gridDim (%u), blockDim (%u), stream launch (%u), #keys on grid (%u keys), offset (%u keys)\n",
            kBlocksPerGrid, kThreadsPerBlock, i, n_cur, offset);
    crypto_kem_enc_kernel<<<kBlocksPerGrid, kThreadsPerBlock, 0, streams[i]>>>(
        d_grid_ct,
        d_grid_ss,
        d_grid_pk,
        d_grid_coins,
        n_cur
    );
  }

  // Launch copy for result of every stream.
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    uint32_t offset = i * kKeysPerGrid;
    uint32_t n_cur = getNKeysForGrid( i);

    uint8_t *h_grid_ct = ct   + offset * KYBER_CIPHERTEXTBYTES;
    uint8_t *h_grid_ss = ss   + offset * KYBER_SSBYTES;
    uint8_t *d_grid_ct = d_ct + offset * KYBER_CIPHERTEXTBYTES;
    uint8_t *d_grid_ss = d_ss + offset * KYBER_SSBYTES;

    GPU_ASSERT( cudaMemcpyAsync( h_grid_ct,
                                 d_grid_ct,
                                 n_cur * KYBER_CIPHERTEXTBYTES,
                                 cudaMemcpyDeviceToHost,
                                 streams[i]));

    GPU_ASSERT( cudaMemcpyAsync( h_grid_ss,
                                 d_grid_ss,
                                 n_cur * KYBER_SSBYTES,
                                 cudaMemcpyDeviceToHost,
                                 streams[i]));
  }

  // Wait for all streams.
  GPU_ASSERT( cudaDeviceSynchronize());

  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    GPU_ASSERT( cudaStreamDestroy( streams[i]));
  }

  cudaFree( d_ct);
  cudaFree( d_ss);
  cudaFree( d_pk);
  cudaFree( d_coins);

  return 0;
}

/*************************************************
* Name:        crypto_kem_dec_kernel
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
__global__ void 
crypto_kem_dec_kernel(uint8_t *ss,
                      const uint8_t *ct,
                      const uint8_t *sk,
                      uint32_t n_keypair)
{
  const int tid = threadIdx.x;
  const int block_size = blockDim.x;
  const int bid = blockIdx.x;
  const int ss_offset = ( bid * block_size + tid ) * KYBER_SSBYTES;
  const int ct_offset = ( bid * block_size + tid ) * KYBER_CIPHERTEXTBYTES;
  const int sk_offset = ( bid * block_size + tid ) * KYBER_SECRETKEYBYTES;

  if ( bid * block_size + tid < n_keypair )
  {
      int fail;
      uint8_t buf[2*KYBER_SYMBYTES];
      /* Will contain key, coins */
      uint8_t kr[2*KYBER_SYMBYTES];
      uint8_t cmp[KYBER_CIPHERTEXTBYTES+KYBER_SYMBYTES];
      const uint8_t *pk = sk + sk_offset + KYBER_INDCPA_SECRETKEYBYTES;

      indcpa_dec(buf, ct + ct_offset, sk + sk_offset);

      /* Multitarget countermeasure for coins + contributory KEM */
      memcpy(buf+KYBER_SYMBYTES, sk + sk_offset + KYBER_SECRETKEYBYTES - 2*KYBER_SYMBYTES, KYBER_SYMBYTES);
      hash_g(kr, buf, 2*KYBER_SYMBYTES);

      /* coins are in kr+KYBER_SYMBYTES */
      indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

      fail = verify(ct + ct_offset, cmp, KYBER_CIPHERTEXTBYTES);

      /* Compute rejection key */
      rkprf(ss + ss_offset, sk + sk_offset + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct + ct_offset);

      /* Copy true key to return buffer if fail is false */
      cmov(ss + ss_offset, kr, KYBER_SYMBYTES, !fail);
  }
}

int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk,
                   uint32_t n_keypair)
{
  const uint32_t n_streams = (n_keypair + kKeysPerGrid - 1) / kKeysPerGrid;
  const uint32_t tail_keypairs = n_keypair % kKeysPerGrid;

  uint8_t *d_ss = nullptr;
  uint8_t *d_ct = nullptr;
  uint8_t *d_sk = nullptr;

  cudaMalloc( &d_ss, n_keypair * KYBER_SSBYTES);
  cudaMalloc( &d_ct, n_keypair * KYBER_CIPHERTEXTBYTES);
  cudaMalloc( &d_sk, n_keypair * KYBER_SECRETKEYBYTES);
  assert( d_ss && d_ct && d_sk);

  std::vector<cudaStream_t> streams( n_streams);
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    GPU_ASSERT( cudaStreamCreate( &streams[i]));
  }

  auto getNKeysForGrid = [=]( uint32_t i) -> uint32_t
  {
    if ( (tail_keypairs != 0) && (i == n_streams - 1) )
    {
      return tail_keypairs;
    } else {
      return kKeysPerGrid;
    }
  };

  // Launch copy for arguments of every stream.
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    uint32_t offset = i * kKeysPerGrid;
    uint32_t n_cur = getNKeysForGrid( i);

    const uint8_t *h_grid_ct = ct   + offset * KYBER_CIPHERTEXTBYTES;
    const uint8_t *h_grid_sk = sk   + offset * KYBER_SECRETKEYBYTES;
    uint8_t       *d_grid_ct = d_ct + offset * KYBER_CIPHERTEXTBYTES;
    uint8_t       *d_grid_sk = d_sk + offset * KYBER_SECRETKEYBYTES;

    GPU_ASSERT( cudaMemcpyAsync( d_grid_ct,
                                 h_grid_ct,
                                 n_cur * KYBER_CIPHERTEXTBYTES,
                                 cudaMemcpyHostToDevice,
                                 streams[i]));

    GPU_ASSERT( cudaMemcpyAsync( d_grid_sk,
                                 h_grid_sk,
                                 n_cur * KYBER_SECRETKEYBYTES,
                                 cudaMemcpyHostToDevice,
                                 streams[i]));
  }

  // Launch all grids in streams.
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    uint32_t offset = i * kKeysPerGrid;
    uint32_t n_cur = getNKeysForGrid( i);

    uint8_t *d_grid_ss = d_ss + offset * KYBER_SSBYTES;
    uint8_t *d_grid_ct = d_ct + offset * KYBER_CIPHERTEXTBYTES;
    uint8_t *d_grid_sk = d_sk + offset * KYBER_SECRETKEYBYTES;

    printf( "dec gridDim (%u), blockDim (%u), stream launch (%u), #keys on grid (%u keys), offset (%u keys)\n",
            kBlocksPerGrid, kThreadsPerBlock, i, n_cur, offset);
    crypto_kem_dec_kernel<<<kBlocksPerGrid, kThreadsPerBlock, 0, streams[i]>>>(
        d_grid_ss,
        d_grid_ct,
        d_grid_sk,
        n_cur
    );
  }

  // Launch copy for result of every stream.
  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    uint32_t offset = i * kKeysPerGrid;
    uint32_t n_cur = getNKeysForGrid( i);

    uint8_t *h_grid_ss = ss   + offset * KYBER_SSBYTES;
    uint8_t *d_grid_ss = d_ss + offset * KYBER_SSBYTES;

    GPU_ASSERT( cudaMemcpyAsync( h_grid_ss,
                                 d_grid_ss,
                                 n_cur * KYBER_SSBYTES,
                                 cudaMemcpyDeviceToHost,
                                 streams[i]));
  }

  // Wait for all streams.
  GPU_ASSERT( cudaDeviceSynchronize());

  for ( uint32_t i = 0; i < n_streams; i++ )
  {
    GPU_ASSERT( cudaStreamDestroy( streams[i]));
  }

  cudaFree( d_ss);
  cudaFree( d_ct);
  cudaFree( d_sk);

  return 0;
}
