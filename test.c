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
    mpz_set_str(publicKey, *rsaGetPubKey(IP), 16);
    mpz_set_str(check, "1232", 16);

    // Print results
    printf("rsaGetPubKey test (should print 1):\n");
    printf("%i\n", mpz_cmp(publicKey, check));

    //
    // TEST 2
    //

    // Initialize and set private key
    char *privateKey = "308f60a9c07f5d08a868ec50e3c40de6cde179d6d36c113e6ee62c1041221360cefb27be849f68551415a1db2c4e44a03558be53011f21b8ed845c936805a6a667ec4ac3c9adc7bbf10518392904d328a44d5a388fb89892e43041079723e671d8b424dbb076aff9b70c336f4449fd20e9393c933e27d65eabe1fea27f3359c8eb1587cae30c33153087dd2164e03ed5daf848c38119efc162900469847d8b2b91bff22a7e90afc1810c0b3310f7e811497bbf1b7260c4cf3b34afbe9a4350fef21f154eeec71df08b5bd3b59494ac26dee367bf9f2c19ea0a9a012c442b67c1ed5bd1841230329d3d6c062644aaf7e8509b19eb176b2a3121b100274555505f3bb5fb6b788dc83ae93c26e02374ae832cad407d759cd5dd4f685ac208e5c2d822688fa8892ede94d5ef39a032371a62c69c63d4f9cda7dc9aaffb2def86b690f25ece47b0da3055ce6f956bd0d6f2d8abcaf8955b4f786671dc5b5de3a919f65fc2cd46bc67a69c57af475a950c15d5f7be9890aca54aff0c9005e0e83f6c6df7bd2bba8b6d9eb0b68a9d2eaf21b587695e6cded992297cea9bbf70a023fa3c76b7636e3b8faaba35e9801052e416ddfab62be7bb541349d60614a92ef09fb87d294c7ad52558369b4104cac882f385e8b32c4dc78a8248943b6722addc9d6ca46b00835bcb2681af519b37aaca2ed7fc82a710592cc15662d63d59d8710709";

    printf("verifySig test (should print 1):\n");
    printf("%i\n", verifySig(IP, "this is the message", rsaEncrypt(sha256("this is the message"), privateKey, *rsaGetPubKey(IP))));

    return 0;
}
