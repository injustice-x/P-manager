#include "../include/context.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  const char *jsonEntr =
      jsonEntries(globalContext->currentUser->currentContext->entries,
                  globalContext->username,
                  globalContext->currentUser->currentContext->entryCount);
  if (jsonEntr == NULL) {
    fprintf(stderr, "jsonEntries returned NULL.\n");
    return -1;
  }

  const unsigned char *plaintext = (const unsigned char *)strdup(jsonEntr);
  globalContext->currentUser->currentContext->crypto->plaintext = plaintext;
  if (plaintext == NULL) {
    fprintf(stderr, "Memory allocation failed.\n");
    free((char *)jsonEntr);
    return -1;
  }
  int plaintext_len = strlen((const char *)plaintext);
  globalContext->currentUser->currentContext->crypto->plaintext_len =
      malloc(sizeof(int));
  if (globalContext->currentUser->currentContext->crypto->plaintext_len != NULL)
    *(globalContext->currentUser->currentContext->crypto->plaintext_len) =
        plaintext_len;

  const unsigned char *key =
      globalContext->currentUser->currentContext->crypto->encryptionKey;

  unsigned char iv[16];
  if (1 != RAND_bytes(iv, sizeof(iv))) {
    fprintf(stderr, "IV generation failed.\n");
    free((void *)plaintext);
    free((char *)jsonEntr);
    return -1;
  }

  /* Allocate memory for iv and copy the generated iv */
  globalContext->currentUser->currentContext->crypto->iv = malloc(sizeof(iv));
  if (globalContext->currentUser->currentContext->crypto->iv == NULL) {
    fprintf(stderr, "Memory allocation failed for iv.\n");
    free((void *)plaintext);
    free((char *)jsonEntr);
    return -1;
  }
  memcpy((void *)globalContext->currentUser->currentContext->crypto->iv, iv,
         sizeof(iv));

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Failed to create context\n");
    free((void *)plaintext);
    free((char *)jsonEntr);
    return -1;
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    fprintf(stderr, "Encryption initialization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    free((void *)plaintext);
    free((char *)jsonEntr);
    return -1;
  }

  int ciphertext_len = plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc());
  globalContext->currentUser->currentContext->crypto->ciphertext_len =
      malloc(sizeof(int));
  unsigned char *ciphertext = malloc(ciphertext_len);
  globalContext->currentUser->currentContext->crypto->ciphertext = ciphertext;
  if (ciphertext == NULL) {
    fprintf(stderr, "Memory allocation failed for ciphertext.\n");
    EVP_CIPHER_CTX_free(ctx);
    free((void *)plaintext);
    free((char *)jsonEntr);
    return -1;
  }

  int len;
  globalContext->currentUser->currentContext->crypto->len = malloc(sizeof(int));
  if (globalContext->currentUser->currentContext->crypto->len != NULL)
    *(globalContext->currentUser->currentContext->crypto->len) = 0;

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    fprintf(stderr, "Encryption update failed\n");
    EVP_CIPHER_CTX_free(ctx);
    free((void *)plaintext);
    free(ciphertext);
    free((char *)jsonEntr);
    return -1;
  }
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    fprintf(stderr, "Encryption finalization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    free((void *)plaintext);
    free(ciphertext);
    free((char *)jsonEntr);
    return -1;
  }
  ciphertext_len += len;
  if (globalContext->currentUser->currentContext->crypto->ciphertext_len !=
      NULL)
    *(globalContext->currentUser->currentContext->crypto->ciphertext_len) =
        ciphertext_len;

  EVP_CIPHER_CTX_free(ctx);
  free((void *)plaintext);

  FILE *file = fopen("encrypted", "wb");
  if (file == NULL) {
    fprintf(stderr, "Failed to open file for writing.\n");
    /* Do not free ciphertext since we want to keep it in globalContext */
    free((char *)jsonEntr);
    return -1;
  }

  if (fwrite(iv, 1, sizeof(iv), file) != sizeof(iv)) {
    fprintf(stderr, "Failed to write IV to file.\n");
    fclose(file);
    free((char *)jsonEntr);
    return -1;
  }

  if (fwrite(ciphertext, 1, ciphertext_len, file) != (size_t)ciphertext_len) {
    fprintf(stderr, "Failed to write ciphertext to file.\n");
    fclose(file);
    free((char *)jsonEntr);
    return -1;
  }

  fclose(file);
  free((char *)jsonEntr);
  return ciphertext_len;
}

int decryptData(passwordManagerContext *globalContext) {
  /* Get ciphertext, ciphertext_len, key, and iv from
   * globalContext->currentUser->currentContext->crypto */
  const unsigned char *ciphertext =
      globalContext->currentUser->currentContext->crypto->ciphertext;
  int ciphertext_len =
      *(globalContext->currentUser->currentContext->crypto->ciphertext_len);
  const unsigned char *key =
      globalContext->currentUser->currentContext->crypto->encryptionKey;
  const unsigned char *iv =
      globalContext->currentUser->currentContext->crypto->iv;

  /* Allocate memory for plaintext; size can be up to ciphertext_len plus block
   * size */
  unsigned char *plaintext =
      malloc(ciphertext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
  if (plaintext == NULL) {
    fprintf(stderr, "Memory allocation failed for plaintext.\n");
    return -1;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len, plaintext_len;
  if (!ctx) {
    fprintf(stderr, "Failed to create context\n");
    free(plaintext);
    return -1;
  }

  /* Initialize decryption operation */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    fprintf(stderr, "Decryption initialization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return -1;
  }

  /* Decrypt the ciphertext */
  if (1 !=
      EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    fprintf(stderr, "Decryption update failed\n");
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return -1;
  }
  plaintext_len = len;

  /* Finalize decryption */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    fprintf(stderr, "Decryption finalization failed\n");
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  /* Store the resulting plaintext and its length back to globalContext */
  globalContext->currentUser->currentContext->crypto->plaintext = plaintext;
  globalContext->currentUser->currentContext->crypto->plaintext_len =
      malloc(sizeof(int));
  if (globalContext->currentUser->currentContext->crypto->plaintext_len != NULL)
    *(globalContext->currentUser->currentContext->crypto->plaintext_len) =
        plaintext_len;

  return plaintext_len;
}
