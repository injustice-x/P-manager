#include "../include/context.h"
#include <openssl/evp.h>
#define DIGEST_SIZE 32 // SHA3-256 produces 32 bytes

unsigned char *hashIt(const char *password, unsigned int *digest_len) {
  unsigned char *digest = malloc(DIGEST_SIZE);
  if (!digest) {
    fprintf(stderr, "Memory allocation error\n");
    return NULL;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Error creating digest context\n");
    free(digest);
    return NULL;
  }

  // Initialize context for SHA3-256
  if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
    fprintf(stderr, "Digest initialization error\n");
    EVP_MD_CTX_free(ctx);
    free(digest);
    return NULL;
  }

  // Update with the password data
  if (EVP_DigestUpdate(ctx, password, strlen(password)) != 1) {
    fprintf(stderr, "Digest update error\n");
    EVP_MD_CTX_free(ctx);
    free(digest);
    return NULL;
  }

  // Finalize the digest calculation
  if (EVP_DigestFinal_ex(ctx, digest, digest_len) != 1) {
    fprintf(stderr, "Digest finalization error\n");
    EVP_MD_CTX_free(ctx);
    free(digest);
    return NULL;
  }

  EVP_MD_CTX_free(ctx);
  return digest;
}
