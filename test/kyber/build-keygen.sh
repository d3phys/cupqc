#!/bin/bash

# g++ -o keygen-test keygen-test.cc -O3 -L ../../cuda/lib -lpqcrystals_kyber512_cuda -L ../../ref/kyber/ref/lib/ -lpqcrystals_kyber512_ref -lpqcrystals_fips202_ref
#g++ -o keygen-perf keygen-perf.cc -O3 -L ../../cuda/lib -lpqcrystals_kyber512_cuda -L ../../ref/kyber/ref/lib/ -lpqcrystals_kyber512_ref -lpqcrystals_fips202_ref
g++ -o keygen-perf keygen-perf.cc -O3 -L ../../cuda/lib -lpqcrystals_kyber768_cuda -L ../../ref/kyber/avx2 -lpqcrystals_kyber768_avx2 -lpqcrystals_fips202_ref -lpqcrystals_fips202x4_avx2

# LD_LIBRARY_PATH="../../cuda/lib;../../ref/kyber/ref/lib" ./a.out
