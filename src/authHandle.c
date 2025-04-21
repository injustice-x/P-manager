#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 50
#define DIGEST_SIZE 32 // SHA3-256
#define IV_SIZE 16     // AES-CBC IV

int addUser(passwordManagerContext *globalContext) {
  char username[MAX_SIZE];
  char password[MAX_SIZE];
  unsigned int ulen = 0, plen = 0;

  // 1) Prompt for username/password
  printf("Enter username: ");
  if (scanf("%49s", username) != 1) {
    fprintf(stderr, "Error reading username\n");
    return EXIT_FAILURE;
  }
  printf("Enter password: ");
  if (scanf("%49s", password) != 1) {
    fprintf(stderr, "Error reading password\n");
    return EXIT_FAILURE;
  }

  // 2) Generate salt and hashes
  char salt[MAX_SIZE + 5];
  snprintf(salt, sizeof(salt), "%ssalt", username);

  unsigned char *uHash = hashIt(username, &ulen);
  unsigned char *pHash = hashIt(password, &plen);
  if (!uHash || !pHash) {
    fprintf(stderr, "Hashing failed\n");
    free(uHash);
    free(pHash);
    return EXIT_FAILURE;
  }

  // 3) Store hashes in globalContext->currentUser->hash
  hashes *h = malloc(sizeof(*h));
  if (!h) {
    perror("malloc(hashes)");
    free(uHash);
    free(pHash);
    return EXIT_FAILURE;
  }
  h->usernameHash = uHash;
  h->passwordHash = pHash;
  globalContext->currentUser->hash = h;

  // 4) Remember the username
  globalContext->username = strdup(username);
  if (!globalContext->username) {
    perror("strdup(username)");
    return EXIT_FAILURE;
  }

  // 5) Initialize userContext
  userContext *ctx = globalContext->currentUser->currentContext;
  ctx->entryCount = 0;

  // 6) Derive encryption key
  ctx->crypto->encryptionKey = deriveAesKey(pHash, plen, salt);
  if (!ctx->crypto->encryptionKey) {
    fprintf(stderr, "Key derivation failed\n");
    return EXIT_FAILURE;
  }

  // 7) Generate IV
  //    generateIV allocates and fills *iv
  if (generateIV(&ctx->crypto->iv) != EXIT_SUCCESS) {
    fprintf(stderr, "IV generation failed.\n");
    return EXIT_FAILURE;
  }

  // 8) Write header (hashes, count, iv) – no ciphertext yet
  if (writeData(globalContext->filePath, h, ctx->entryCount, ctx->crypto->iv,
                NULL, // no ciphertext yet
                0) != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to write initial vault data\n");
    return EXIT_FAILURE;
  }

  printf("User created successfully.\n");
  return EXIT_SUCCESS;
}

int getUser(passwordManagerContext *globalContext) {
  char username[MAX_SIZE], password[MAX_SIZE];
  unsigned int ulen = 0, plen = 0;

  // 1) Prompt for credentials
  printf("Enter username: ");
  if (scanf("%49s", username) != 1) {
    fprintf(stderr, "Error reading username\n");
    return EXIT_FAILURE;
  }
  printf("Enter password: ");
  if (scanf("%49s", password) != 1) {
    fprintf(stderr, "Error reading password\n");
    return EXIT_FAILURE;
  }

  // 2) Build salt and hash the inputs
  char salt[MAX_SIZE + 5];
  snprintf(salt, sizeof(salt), "%ssalt", username);

  unsigned char *uHashIn = hashIt(username, &ulen);
  unsigned char *pHashIn = hashIt(password, &plen);
  if (!uHashIn || !pHashIn) {
    fprintf(stderr, "Hashing failed\n");
    free(uHashIn);
    free(pHashIn);
    return EXIT_FAILURE;
  }

  // 3) Read stored header into currentUser->hash
  userContext *ctx = globalContext->currentUser->currentContext;
  hashes *stored = globalContext->currentUser->hash;
  // Ensure the buffers exist
  stored->usernameHash = malloc(DIGEST_SIZE);
  stored->passwordHash = malloc(DIGEST_SIZE);
  if (!stored->usernameHash || !stored->passwordHash) {
    perror("malloc(hashes)");
    free(uHashIn);
    free(pHashIn);
    free(stored->usernameHash);
    free(stored->passwordHash);
    return EXIT_FAILURE;
  }

  if (getData(globalContext->filePath, stored, &ctx->entryCount,
              &ctx->crypto->iv, &ctx->crypto->ciphertext,
              ctx->crypto->ciphertext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to load vault data\n");
    free(uHashIn);
    free(pHashIn);
    free(stored->usernameHash);
    free(stored->passwordHash);
    return EXIT_FAILURE;
  }

  // 4) Compare full hashes
  if (memcmp(stored->usernameHash, uHashIn, DIGEST_SIZE) != 0 ||
      memcmp(stored->passwordHash, pHashIn, DIGEST_SIZE) != 0) {
    fprintf(stderr, "Login failed: incorrect credentials\n");
    free(uHashIn);
    free(pHashIn);
    return EXIT_FAILURE;
  }

  // 5) Success: record username & derive key
  if (!(globalContext->username = strdup(username))) {
    perror("strdup(username)");
    free(uHashIn);
    free(pHashIn);
    return EXIT_FAILURE;
  }
  ctx->crypto->encryptionKey = deriveAesKey(pHashIn, plen, salt);
  if (!ctx->crypto->encryptionKey) {
    fprintf(stderr, "Key derivation failed\n");
    free(uHashIn);
    free(pHashIn);
    return EXIT_FAILURE;
  }

  printf("Login successful. %d entries loaded.\n", ctx->entryCount);

  // 6) Clean up input hashes; keep stored hashes for later IO
  free(uHashIn);
  free(pHashIn);

  return EXIT_SUCCESS;
}
