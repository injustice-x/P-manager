#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define DIGEST_SIZE 32  // SHA3-256 produces 32 bytes

// Helper to convert binary digest to hex string.
void print_digest(const unsigned char *digest, unsigned int len) {
    for (unsigned int i = 0; i < len; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

int main(void) {
    // The input message.
    const char *msg = "fklsjhfgsdgkf";
    unsigned char digest[DIGEST_SIZE];
    unsigned int digest_len = 0;

    // Create and initialize a digest context.
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating context\n");
        return 1;
    }

    // Initialize the context to use SHA3-256.
    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        fprintf(stderr, "Digest initialization error\n");
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    // Hash the data.
    if (EVP_DigestUpdate(ctx, msg, strlen(msg)) != 1) {
        fprintf(stderr, "Digest update error\n");
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    // Finalize the digest.
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        fprintf(stderr, "Digest finalization error\n");
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    EVP_MD_CTX_free(ctx);

    printf("SHA3-256 digest: ");
    print_digest(digest, digest_len);

    return 0;
}
