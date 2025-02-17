#include "../include/hashPass.h"

// This function computes the SHA3-256 hash of the given mPass.
unsigned char *hashPass(char *mPass) {
  // Create and initialize a new digest context.
  unsigned char *hash = malloc(EVP_MD_size(EVP_sha3_256()));
  unsigned int hash_len = 0;
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    fprintf(stderr, "Error: EVP_MD_CTX_new() failed.\n");
    return NULL;
  }

  // Initialize the digest context to use SHA3-256.
  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) {
    fprintf(stderr, "Error: EVP_DigestInit_ex() failed.\n");
    EVP_MD_CTX_free(mdctx);
    return NULL;
  }

  // Feed the mPass into the digest.
  if (1 != EVP_DigestUpdate(mdctx, mPass, strlen(mPass))) {
    fprintf(stderr, "Error: EVP_DigestUpdate() failed.\n");
    EVP_MD_CTX_free(mdctx);
    return NULL;
  }

  // Finalize the digest and obtain the hash.
  if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
    fprintf(stderr, "Error: EVP_DigestFinal_ex() failed.\n");
    EVP_MD_CTX_free(mdctx);
    return NULL;
  }

  // Clean up the digest context.
  EVP_MD_CTX_free(mdctx);

  // Print the resulting hash in hexadecimal.
  printf("SHA3-256(\"%s\") = ", mPass);
  for (unsigned int i = 0; i < hash_len; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");

  return hash;
}
