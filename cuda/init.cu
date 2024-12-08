#include <assert.h>
#include "kem.h"

int pqcrystals_init()
{
    assert( !cudaFree(0));

    assert( !cudaFuncSetCacheConfig( crypto_kem_keypair_kernel, cudaFuncCachePreferL1));
    assert( !cudaFuncSetCacheConfig( crypto_kem_enc_kernel, cudaFuncCachePreferL1));
    assert( !cudaFuncSetCacheConfig( crypto_kem_dec_kernel, cudaFuncCachePreferL1));

    return 0;
}
