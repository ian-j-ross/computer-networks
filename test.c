#include <gmp.h>
#include <stdio.h>
#include "rsa.h"
#include "rsa.c"

int main(int argc, char const *argv[])
{
    char *IP = "10.35.70.27";
    mpz_t publicKey;
    mpz_t check;

    printf("Test print\n");

    mpz_inits(publicKey, check, NULL);

    rsaGetPubKey(IP, &publicKey);

    mpz_set_str(check, "1232", 16);

    printf("%i", memcmp(publicKey, check, 8) == 0);

    return 0;
}
