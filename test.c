#include <gmp.h>
#include "rsa.h"
#include "rsa.c"

int main(int argc, char const *argv[])
{
    char *IP = "10.35.70.27";
    mpz_t publicKey;
    mpz_t check;

    mpz_inits(publiKey, check, NULL);

    rsaGetPubKey(IP, *publicKey);

    mpz_setstr(publicKey, "1232");

    printf("%i", memcmp());

    return 0;
}
