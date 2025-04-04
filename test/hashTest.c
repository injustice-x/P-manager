#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIGEST_SIZE 32 // SHA3-256 produces 32 bytes

unsigned char *hashIt(const char *input, unsigned int *digest_len) {
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

  // Update with the input data
  if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1) {
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

int main() {
  const char *input = "The quick brown fox jumps over the lazy dog";
  unsigned int digest_len = 0;

  unsigned char *digest = hashIt(input, &digest_len);
  if (!digest) {
    fprintf(stderr, "Hash computation failed\n");
    return EXIT_FAILURE;
  }

  // Print the digest as a hexadecimal string
  printf("SHA3-256 digest: ");
  for (unsigned int i = 0; i < digest_len; ++i) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  free(digest);
  return EXIT_SUCCESS;
}
