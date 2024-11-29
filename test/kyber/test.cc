#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "test-api.hh"

int testHandshake()
{
    uint8_t publicKey[kyberPublicKeyBytes];
    uint8_t secretKey[kyberSecretKeyBytes];
    uint8_t cipherText[kyberCipherTextBytes];

    uint8_t keyA[kyberBytes];
    uint8_t keyB[kyberBytes];

    uint8_t encCoins[kyber768EncCoinBytes];
    for ( int i = 0; i != kyber768EncCoinBytes; ++i )
    {
        encCoins[i] = i;
    }

    uint8_t keyPairCoins[kyber768KeyPairCoinBytes];
    for ( int i = 0; i != kyber768KeyPairCoinBytes; ++i )
    {
        keyPairCoins[i] = i;
    }

    // Alice generates a public key
    kyberKeyPairDeRand( publicKey, secretKey, keyPairCoins);

    // Bob derives a secret key and creates a response
    kyberEncDeRand( cipherText, keyB, publicKey, encCoins);

    // Alice uses Bobs response to get her shared key
    kyberDec( keyA, cipherText, secretKey);

    if ( memcmp( keyA, keyB, kyberBytes) ) 
    {
        printf("ERROR keys\n");
        return 1;
    }

    return 0;
}

int main()
{
    assert( testHandshake() == 0 );
}

