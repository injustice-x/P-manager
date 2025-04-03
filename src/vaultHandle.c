#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#define MAX_NAME_LEN 100
#define MAX_USERNAME_LEN 100
#define MAX_PASSWORD_LEN 100
#define MAX_WEBSITE_LEN 100

int showVault(passwordManagerContext *globalContext) {
  if (globalContext == NULL || globalContext->currentUser == NULL ||
      globalContext->currentUser->currentContext == NULL) {
    fprintf(stderr, "Invalid global context\n");
    return EXIT_FAILURE;
  }

  userContext *context = globalContext->currentUser->currentContext;
  int noEntries = context->entryCount;

  if (noEntries == 0) {
    printf("Vault is Empty!!!\n");
    return EXIT_SUCCESS;
  }

  if (context->entries == NULL) {
    fprintf(stderr, "Entries are not loaded\n");
    return EXIT_FAILURE;
  }

  printf("Vault Entries:\n");
  for (int i = 0; i < noEntries; i++) {
    printf("Entry %d:\n", i + 1);
    printf("  Name: %s\n", context->entries[i].name);
    printf("  Username: %s\n", context->entries[i].username);
    printf("  Password: %s\n", context->entries[i].password);
    printf("  Website: %s\n", context->entries[i].website);
    printf("\n");
  }

  return EXIT_SUCCESS;
}

int addEntry(passwordManagerContext *globalContext) {
  if (globalContext == NULL || globalContext->currentUser == NULL ||
      globalContext->currentUser->currentContext == NULL) {
    fprintf(stderr, "Invalid global context\n");
    return EXIT_FAILURE;
  }

  userContext *context = globalContext->currentUser->currentContext;
  int newSize = context->entryCount + 1;

  entry *tempEntries = realloc(context->entries, newSize * sizeof(entry));
  if (tempEntries == NULL) {
    perror("Memory reallocation failed");
    return EXIT_FAILURE;
  }
  context->entries = tempEntries;

  entry *newEntry = &context->entries[context->entryCount];

  newEntry->name = malloc(MAX_NAME_LEN);
  newEntry->username = malloc(MAX_USERNAME_LEN);
  newEntry->password = malloc(MAX_PASSWORD_LEN);
  newEntry->website = malloc(MAX_WEBSITE_LEN);

  if (!newEntry->name || !newEntry->username || !newEntry->password ||
      !newEntry->website) {
    perror("Memory allocation failed for entry fields");
    free(newEntry->name);
    free(newEntry->username);
    free(newEntry->password);
    free(newEntry->website);
    return EXIT_FAILURE;
  }

  printf("Enter name of the entry: ");
  if (fgets(newEntry->name, MAX_NAME_LEN, stdin) == NULL) {
    fprintf(stderr, "Error reading name\n");
    free(newEntry->name);
    free(newEntry->username);
    free(newEntry->password);
    free(newEntry->website);
    return EXIT_FAILURE;
  }
  newEntry->name[strcspn(newEntry->name, "\n")] = '\0';

  printf("Enter username: ");
  if (fgets(newEntry->username, MAX_USERNAME_LEN, stdin) == NULL) {
    fprintf(stderr, "Error reading username\n");
    free(newEntry->name);
    free(newEntry->username);
    free(newEntry->password);
    free(newEntry->website);
    return EXIT_FAILURE;
  }
  newEntry->username[strcspn(newEntry->username, "\n")] = '\0';

  printf("Enter password: ");
  if (fgets(newEntry->password, MAX_PASSWORD_LEN, stdin) == NULL) {
    fprintf(stderr, "Error reading password\n");
    free(newEntry->name);
    free(newEntry->username);
    free(newEntry->password);
    free(newEntry->website);
    return EXIT_FAILURE;
  }
  newEntry->password[strcspn(newEntry->password, "\n")] = '\0';

  printf("Enter website: ");
  if (fgets(newEntry->website, MAX_WEBSITE_LEN, stdin) == NULL) {
    fprintf(stderr, "Error reading website\n");
    free(newEntry->name);
    free(newEntry->username);
    free(newEntry->password);
    free(newEntry->website);
    return EXIT_FAILURE;
  }
  newEntry->website[strcspn(newEntry->website, "\n")] = '\0';

  context->entryCount++;

  int ciphertext_len = encryptData(globalContext);
  if (ciphertext_len < 0) {
    fprintf(stderr, "Encryption failed\n");
    return EXIT_FAILURE;
  }

  // Write the encrypted data to the file
  if (writeData((unsigned char *)globalContext->currentUser->currentContext
                    ->crypto->ciphertext,
                globalContext->filePath, context->entryCount) != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to write encrypted data to file\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
