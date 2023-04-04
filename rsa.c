#include <gmp.h>
#include "rsa.h"

char Node_IPs[5][16] = {
    "10.35.70.7",
    "10.35.70.27",
    "10.35.70.37",
    "10.35.70.47",
    "10.35.70.57"};

char Node_PubKeys[5][RSA_KEYLEN] = {
    "ABC1",
    "1232",
    "4563",
    "89F4",
    "7D05"};

void rsaGetPubKey(char *IP, mpz_t *publicKey)
{
    mpz_init(publicKey)

        for (int i = 0; i < NUM_NODES; i++)
    {
        if (strcmp(IP, Node_IPs[i]) == 0)
        {
            // If IP is found in the network list, find public Key
            mpz_setstr(publicKey, Node_PubKeys[i]);

            return;
        }
    }

    mpz_setstr(publicKey, NULL);
}