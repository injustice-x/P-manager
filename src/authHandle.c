#include "../include/context.h"
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
  int yes = writeHashes(hash, globalContext->filePath);

  printf("\nUsername: %s\nPassword: %s\n", username, password);
  free(username);
  free(password);
  return 0;
}
