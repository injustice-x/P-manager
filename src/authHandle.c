#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 50
#define DIGEST_SIZE 32 // SHA3-256 produces 32 bytes

int addUser(passwordManagerContext *globalContext) {
  char *username = malloc(MAX_SIZE);
  char *password = malloc(MAX_SIZE);
  char *salt;
  unsigned int usernameHashLen = 0;
  unsigned int passwordHashLen = 0;

  hashes *hash = globalContext->currentUser->hash;
  hash->passwordHash = malloc(DIGEST_SIZE);
  hash->usernameHash = malloc(DIGEST_SIZE);

  printf("Enter the username: ");
  scanf("%49s", username); // %49s to prevent buffer overflow
  hash->usernameHash = hashIt(username, &usernameHashLen);

  printf("Enter the password: ");
  scanf("%49s", password);
  salt = strcat(username, "salt");

  hash->passwordHash = hashIt(password, &passwordHashLen);
  writeHashes(hash, globalContext->filePath, 0);
  userContext *currentContext = globalContext->currentUser->currentContext;
  currentContext->entryCount = 0;
  globalContext->username = strdup(username);
  printf("\nUsername: %s\nPassword: %s\n", globalContext->username, password);

  globalContext->currentUser->currentContext->encryptionKey =
      deriveAesKey(hash->passwordHash, passwordHashLen, salt);

  free(username);
  free(password);
  return 0;
}

int getUser(passwordManagerContext *globalContext) {
  char *salt;
  hashes *temp = malloc(sizeof(hashes));

  temp = getHashes(globalContext->filePath);
  temp->passwordHash = malloc(DIGEST_SIZE);
  temp->usernameHash = malloc(DIGEST_SIZE);

  char *username = malloc(MAX_SIZE);
  char *password = malloc(MAX_SIZE);
  unsigned int usernameHashLen = 0;
  unsigned int passwordHashLen = 0;

  printf("Enter the username: ");
  scanf("%49s", username); // %49s to prevent buffer overflow
  temp->usernameHash = hashIt(username, &usernameHashLen);

  printf("Enter the password: ");
  scanf("%49s", password);
  temp->passwordHash = hashIt(password, &passwordHashLen);

  hashes *hash = globalContext->currentUser->hash;
  hash->passwordHash = malloc(DIGEST_SIZE);
  hash->usernameHash = malloc(DIGEST_SIZE);

  hash = getHashes(globalContext->filePath);

  if (*hash->usernameHash != *temp->usernameHash ||
      *hash->passwordHash != *temp->passwordHash) {
    printf("login failed");
    free(username);
    free(password);
    free(salt);
    return 0;
  } else
    printf("success");

  globalContext->username = strdup(username);
  salt = strcat(username, "salt");
  globalContext->currentUser->currentContext->encryptionKey =
      deriveAesKey(hash->passwordHash, passwordHashLen, salt);

  free(username);
  free(password);
  return 0;
}
