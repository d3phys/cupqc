#!/bin/bash
mkdir -p build

# LD_LIBRARY_PATH=../../ref/kyber/ref/lib ./build/test.ref
g++ -o build/test.ref test.cc ref/ref/test-api.cc -O3 -L ../../ref/kyber/ref/lib/ -lpqcrystals_fips202_ref -lpqcrystals_kyber512_ref -lpqcrystals_kyber768_ref

# LD_LIBRARY_PATH=../../ref/kyber/avx2 ./build/test.avx2
g++ -o build/test.avx2 test.cc ref/avx2/test-api.cc -O3 -L ../../ref/kyber/avx2/ -lpqcrystals_fips202_ref -lpqcrystals_fips202x4_avx2 -lpqcrystals_kyber512_avx2 -lpqcrystals_kyber768_avx2
