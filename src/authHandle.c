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
  unsigned int usernameHashLen = 0;
  unsigned int passwordHashLen = 0;

  // Prompt for username
  printf("Enter the username: ");
  if (scanf("%49s", username) != 1) {
    fprintf(stderr, "Error reading username.\n");
    return EXIT_FAILURE;
  }

  // Prompt for password
  printf("Enter the password: ");
  if (scanf("%49s", password) != 1) {
    fprintf(stderr, "Error reading password.\n");
    return EXIT_FAILURE;
  }

  // Generate salt by concatenating username with "salt"
  char salt[MAX_SIZE + 5];
  snprintf(salt, sizeof(salt), "%ssalt", username);

  // Hash username and password
  unsigned char *usernameHash = hashIt(username, &usernameHashLen);
  unsigned char *passwordHash = hashIt(password, &passwordHashLen);
  if (!usernameHash || !passwordHash) {
    fprintf(stderr, "Hashing failed.\n");
    return EXIT_FAILURE;
  }

  // Allocate and assign hashes
  hashes *hash = malloc(sizeof(hashes));
  if (!hash) {
    fprintf(stderr, "Memory allocation failed for hashes.\n");
    free(usernameHash);
    free(passwordHash);
    return EXIT_FAILURE;
  }
  hash->usernameHash = usernameHash;
  hash->passwordHash = passwordHash;
  globalContext->currentUser->hash = hash;

  // Set username in global context
  globalContext->username = strdup(username);
  if (!globalContext->username) {
    fprintf(stderr, "Memory allocation failed for username.\n");
    return EXIT_FAILURE;
  }

  // Initialize user context
  userContext *currentContext = globalContext->currentUser->currentContext;
  currentContext->entryCount = 0;

  // Derive encryption key
  currentContext->crypto->encryptionKey =
      deriveAesKey(passwordHash, passwordHashLen, salt);
  if (!currentContext->crypto->encryptionKey) {
    fprintf(stderr, "Key derivation failed.\n");
    return EXIT_FAILURE;
  }

  // Generate IV
  currentContext->crypto->iv = malloc(IV_SIZE);
  if (!currentContext->crypto->iv) {
    fprintf(stderr, "Memory allocation failed for IV.\n");
    return EXIT_FAILURE;
  }
  if (generateIV(&currentContext->crypto->iv) != EXIT_SUCCESS) {
    fprintf(stderr, "IV generation failed.\n");
    return EXIT_FAILURE;
  }

  // Write data to file
  if (writeData(globalContext->filePath, hash, currentContext->entryCount,
                currentContext->crypto->iv, NULL, 0) != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to write data.\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int getUser(passwordManagerContext *globalContext) {
  char username[MAX_SIZE];
  char password[MAX_SIZE];
  unsigned int usernameHashLen = 0;
  unsigned int passwordHashLen = 0;

  // Prompt for username
  printf("Enter the username: ");
  if (scanf("%49s", username) != 1) {
    fprintf(stderr, "Error reading username.\n");
    return EXIT_FAILURE;
  }

  // Prompt for password
  printf("Enter the password: ");
  if (scanf("%49s", password) != 1) {
    fprintf(stderr, "Error reading password.\n");
    return EXIT_FAILURE;
  }

  // Generate salt
  char salt[MAX_SIZE + 5];
  snprintf(salt, sizeof(salt), "%ssalt", username);

  // Hash input username and password
  unsigned char *inputUsernameHash = hashIt(username, &usernameHashLen);
  unsigned char *inputPasswordHash = hashIt(password, &passwordHashLen);
  if (!inputUsernameHash || !inputPasswordHash) {
    fprintf(stderr, "Hashing failed.\n");
    return EXIT_FAILURE;
  }

  // Allocate memory for stored hashes
  hashes *storedHash = malloc(sizeof(hashes));
  if (!storedHash) {
    fprintf(stderr, "Memory allocation failed for stored hashes.\n");
    return EXIT_FAILURE;
  }
  storedHash->usernameHash = malloc(DIGEST_SIZE);
  storedHash->passwordHash = malloc(DIGEST_SIZE);
  if (!storedHash->usernameHash || !storedHash->passwordHash) {
    fprintf(stderr, "Memory allocation failed for hash buffers.\n");
    return EXIT_FAILURE;
  }

  // Read data from file
  userContext *currentContext = globalContext->currentUser->currentContext;
  if (getData(globalContext->filePath, storedHash, &currentContext->entryCount,
              &currentContext->crypto->iv, &currentContext->crypto->ciphertext,
              currentContext->crypto->ciphertext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to read data.\n");
    return EXIT_FAILURE;
  }

  // Compare hashes
  if (memcmp(storedHash->usernameHash, inputUsernameHash, DIGEST_SIZE) != 0 ||
      memcmp(storedHash->passwordHash, inputPasswordHash, DIGEST_SIZE) != 0) {
    fprintf(stderr, "Login failed: Incorrect username or password.\n");
    return EXIT_FAILURE;
  }

  // Set username in global context
  globalContext->username = strdup(username);
  if (!globalContext->username) {
    fprintf(stderr, "Memory allocation failed for username.\n");
    return EXIT_FAILURE;
  }

  // Derive encryption key
  currentContext->crypto->encryptionKey =
      deriveAesKey(inputPasswordHash, passwordHashLen, salt);
  if (!currentContext->crypto->encryptionKey) {
    fprintf(stderr, "Key derivation failed.\n");
    return EXIT_FAILURE;
  }

  printf("Login successful.\n");
  return EXIT_SUCCESS;
}
