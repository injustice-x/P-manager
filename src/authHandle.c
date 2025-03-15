#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE 50
#define DIGEST_SIZE 32 // SHA3-256 produces 32 bytes

int addUser(passwordManagerContext *globalContext) {
  char *username = malloc(MAX_SIZE);
  char *password = malloc(MAX_SIZE);
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

  hash->passwordHash = hashIt(password, &passwordHashLen);
  writeHashes(hash, globalContext->filePath);
  userContext *currentContext = globalContext->currentUser->currentContext;
  currentContext->entryCount = 0;
  printf("\nUsername: %s\nPassword: %s\n", username, password);
  free(username);
  free(password);
  return 0;
}

int getUser(passwordManagerContext *globalContext) {

  hashes *temp = malloc(sizeof(hashes));
  temp = getHashes(globalContext->filePath);
  temp->passwordHash = malloc(DIGEST_SIZE);
  temp->usernameHash = malloc(DIGEST_SIZE);

  for (unsigned int i = 0; i < 32; ++i) {
    printf("%02x", temp->passwordHash[i]);
  }

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
    printf("fail");
  } else
    printf("success");
  return 0;
}
