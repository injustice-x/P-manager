#include "../include/context.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DIGEST_SIZE 32 // SHA3-256 produces 32 bytes
#define IV_SIZE 16

int generateIV(unsigned char **iv) {
  // 1) Allocate
  *iv = malloc(IV_SIZE);
  if (!*iv) {
    fprintf(stderr, "Memory allocation failed for IV.\n");
    return EXIT_FAILURE;
  }

  // 2) Fill with cryptographically secure random bytes
  if (RAND_bytes(*iv, IV_SIZE) != 1) {
    fprintf(stderr, "IV generation failed.\n");
    free(*iv);
    *iv = NULL;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
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

int encryptData(unsigned char *plaintext, int *plaintext_len,
                const unsigned char *key, unsigned char **iv,
                unsigned char **ciphertext, int *ciphertext_len) {
  EVP_CIPHER_CTX *ctx = NULL;
  int len = 0;
  int total_len = 0;

  // Allocate memory for IV
  *iv = (unsigned char *)malloc(IV_SIZE);
  if (*iv == NULL) {
    fprintf(stderr, "Memory allocation failed for IV.\n");
    return EXIT_FAILURE;
  }

  // Generate random IV
  generateIV(iv);

  // Create and initialize the context
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");
    free(*iv);
    return EXIT_FAILURE;
  }

  // Initialize the encryption operation with AES-256-CBC
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, *iv)) {
    fprintf(stderr, "EVP_EncryptInit_ex failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    free(*iv);
    return EXIT_FAILURE;
  }

  // Allocate memory for ciphertext
  *ciphertext = (unsigned char *)malloc(
      *plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
  if (*ciphertext == NULL) {
    fprintf(stderr, "Memory allocation failed for ciphertext.\n");
    EVP_CIPHER_CTX_free(ctx);
    free(*iv);
    return EXIT_FAILURE;
  }

  // Perform the encryption
  if (1 !=
      EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, *plaintext_len)) {
    fprintf(stderr, "EVP_EncryptUpdate failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    free(*iv);
    free(*ciphertext);
    return EXIT_FAILURE;
  }
  total_len = len;

  // Finalize the encryption
  if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
    fprintf(stderr, "EVP_EncryptFinal_ex failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    free(*iv);
    free(*ciphertext);
    return EXIT_FAILURE;
  }
  total_len += len;

  // Set the ciphertext length
  *ciphertext_len = total_len;

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return EXIT_SUCCESS;
}

int decryptData(unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, unsigned char *iv,
                unsigned char **plaintext, int *plaintext_len) {
  EVP_CIPHER_CTX *ctx = NULL;
  int len = 0;
  int total_len = 0;

  // Create and initialize the context
  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");
    return EXIT_FAILURE;
  }

  // Initialize the decryption operation with AES-256-CBC
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    fprintf(stderr, "EVP_DecryptInit_ex failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    return EXIT_FAILURE;
  }

  // Allocate memory for plaintext
  *plaintext = (unsigned char *)malloc(ciphertext_len);
  if (*plaintext == NULL) {
    fprintf(stderr, "Memory allocation failed for plaintext.\n");
    EVP_CIPHER_CTX_free(ctx);
    return EXIT_FAILURE;
  }

  // Perform the decryption
  if (1 !=
      EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
    fprintf(stderr, "EVP_DecryptUpdate failed.\n");
    EVP_CIPHER_CTX_free(ctx);
    free(*plaintext);
    return EXIT_FAILURE;
  }
  total_len = len;

  // Finalize the decryption
  if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
    fprintf(stderr, "EVP_DecryptFinal_ex failed. Possible incorrect key or "
                    "corrupted data.\n");
    EVP_CIPHER_CTX_free(ctx);
    free(*plaintext);
    return EXIT_FAILURE;
  }
  total_len += len;

  // Set the plaintext length
  *plaintext_len = total_len;

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return EXIT_SUCCESS;
}
