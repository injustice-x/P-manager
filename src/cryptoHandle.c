#include "../include/context.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <time.h>

#define DIGEST_SIZE 32 // SHA3-256 produces 32 bytes

unsigned char *hashIt(char *input, unsigned int *digest_len) {
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

unsigned char *deriveAesKey(unsigned char *master_hash, size_t hash_len,
                            char *user_salt) {
  // Internal fixed parameters
  const int iterations =
      10000;                 // Adjust for desired security/performance balance
  const int key_length = 32; // 32 bytes for AES-256

  // Allocate memory for the derived key
  unsigned char *aes_key = malloc(key_length);
  if (aes_key == NULL) {
    fprintf(stderr, "Memory allocation failed.\n");
    return NULL;
  }

  // Derive the key using PBKDF2-HMAC-SHA256.
  // The function uses the master_hash as the "password" and user_salt as the
  // salt.
  if (!PKCS5_PBKDF2_HMAC((const char *)master_hash, hash_len,
                         (const unsigned char *)user_salt, strlen(user_salt),
                         iterations, EVP_sha256(), key_length, aes_key)) {
    fprintf(stderr, "Key derivation failed.\n");
    free(aes_key);
    return NULL;
  }

  return aes_key;
}
int encryptData(passwordManagerContext *globalContext) {

  char *jsonEntr =
      jsonEntries(globalContext->currentUser->currentContext->entries,
                  globalContext->username,
                  globalContext->currentUser->currentContext->entryCount);

  return EXIT_SUCCESS;
}

int decryptData(passwordManagerContext *globalContext) { return EXIT_SUCCESS; }
