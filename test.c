#include <gmp.h>
#include <stdio.h>
#include "rsa.h"
#include "rsa.c"

int main(int argc, char const *argv[])
{
    // Initial constants and initializations
    char *IP = "10.35.70.27";
    mpz_t publicKey;
    mpz_t check;
    mpz_inits(publicKey, check, NULL);

    //
    // TEST 1
    //

    // Should set to the same thing
    rsaGetPubKey(IP, &publicKey);
    mpz_set_str(check, "1232", 16);

    // Print results
    printf("rsaGetPubKey test (should print 1):\n");
    printf("%i\n", mpz_cmp(publicKey, check));

    //
    // TEST 2
    //

    // Initialize and set private key
    mpz_t privateKey;
    mpz_init(privateKey);
    mpz_set_str(privateKey, "4321", 16);

    printf("rsaGetPubKey test (should print 1):\n");
    printf("%i\n", verifySig(IP, "4321", "4321"));

    return 0;
}
