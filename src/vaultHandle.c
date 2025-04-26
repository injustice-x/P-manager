#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_LEN 100
#define MAX_USERNAME_LEN 100
#define MAX_PASSWORD_LEN 100
#define MAX_WEBSITE_LEN 100

int addEntry(passwordManagerContext *globalContext) {
  if (!globalContext || !globalContext->currentUser ||
      !globalContext->currentUser->currentContext) {
    fprintf(stderr, "Invalid global context\n");
    return EXIT_FAILURE;
  }

  userContext *ctx = globalContext->currentUser->currentContext;
  cryptoContext *crypto = ctx->crypto;
  int oldCount = ctx->entryCount;
  entry *oldEntries = ctx->entries;

  if (getData(globalContext->filePath, globalContext->currentUser->hash,
              &ctx->entryCount, &crypto->iv, &crypto->ciphertext,
              &crypto->ciphertext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to read vault data\n");
    return EXIT_FAILURE;
  }
  if (decryptData(crypto->ciphertext, crypto->ciphertext_len,
                  crypto->encryptionKey, crypto->iv, &crypto->plaintext,
                  crypto->plaintext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Decryption failed\n");
    free(crypto->ciphertext);
    return EXIT_FAILURE;
  }
  ctx->entries = unJsonEntries((char *)crypto->plaintext, &ctx->entryCount);

  if (!ctx->entries && ctx->entryCount > 0) {
    fprintf(stderr, "Failed to parse JSON entries\n");
    return EXIT_FAILURE;
  }
  // 1) Expand entries array
  entry *newEntries = realloc(ctx->entries, (oldCount + 1) * sizeof(entry));
  if (!newEntries) {
    perror("realloc failed");
    return EXIT_FAILURE;
  }
  ctx->entries = newEntries;
  entry *e = &ctx->entries[oldCount];

  // 2) Allocate fields
  e->name = malloc(MAX_NAME_LEN);
  e->username = malloc(MAX_USERNAME_LEN);
  e->password = malloc(MAX_PASSWORD_LEN);
  e->website = malloc(MAX_WEBSITE_LEN);
  if (!e->name || !e->username || !e->password || !e->website) {
    fprintf(stderr, "Allocation failed\n");
    // rollback
    ctx->entries = oldEntries;
    free(e->name);
    free(e->username);
    free(e->password);
    free(e->website);
    return EXIT_FAILURE;
  }

  // 3) Read inputs safely
  printf("Enter name: ");
  if (!fgets(e->name, MAX_NAME_LEN, stdin)) {
    fprintf(stderr, "Error reading name\n");
    goto rollback_fields;
  }
  e->name[strcspn(e->name, "\n")] = '\0';

  printf("Enter username: ");
  if (!fgets(e->username, MAX_USERNAME_LEN, stdin)) {
    fprintf(stderr, "Error reading username\n");
    goto rollback_fields;
  }
  e->username[strcspn(e->username, "\n")] = '\0';

  printf("Enter password: ");
  if (!fgets(e->password, MAX_PASSWORD_LEN, stdin)) {
    fprintf(stderr, "Error reading password\n");
    goto rollback_fields;
  }
  e->password[strcspn(e->password, "\n")] = '\0';

  printf("Enter website: ");
  if (!fgets(e->website, MAX_WEBSITE_LEN, stdin)) {
    fprintf(stderr, "Error reading website\n");
    goto rollback_fields;
  }
  e->website[strcspn(e->website, "\n")] = '\0';

  // 4) Serialize to JSON
  crypto->plaintext = NULL;
  unsigned char *json = (unsigned char *)jsonEntries(
      ctx->entries, globalContext->username, oldCount + 1);
  if (!json) {
    fprintf(stderr, "JSON serialization failed\n");
    goto rollback_fields;
  }
  crypto->plaintext = json;
  *crypto->plaintext_len = strlen((char *)json);

  // 5) Encrypt and zero plaintext
  if (encryptData(crypto->plaintext, crypto->plaintext_len,
                  crypto->encryptionKey, &crypto->iv, &crypto->ciphertext,
                  &crypto->ciphertext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Encryption failed\n");
    goto rollback_fields;
  }
  explicit_bzero(crypto->plaintext, *crypto->plaintext_len);

  // 6) Write out
  if (writeData(globalContext->filePath, globalContext->currentUser->hash,
                oldCount + 1, crypto->iv, crypto->ciphertext,
                &crypto->ciphertext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Write failed\n");
    free(crypto->ciphertext);
    goto rollback_fields;
  }

  ctx->entryCount++;
  return EXIT_SUCCESS;

rollback_fields:
  // Cleanup on any field‐read or later failure
  free(e->name);
  free(e->username);
  explicit_bzero(e->password, strlen(e->password));
  free(e->password);
  free(e->website);
  ctx->entries = oldEntries;
  return EXIT_FAILURE;
}

int showVault(passwordManagerContext *globalContext) {
  if (!globalContext || !globalContext->currentUser ||
      !globalContext->currentUser->currentContext) {
    fprintf(stderr, "Invalid global context\n");
    return EXIT_FAILURE;
  }

  userContext *ctx = globalContext->currentUser->currentContext;
  cryptoContext *crypto = ctx->crypto;

  if (ctx->entries == NULL) {
    if (getData(globalContext->filePath, globalContext->currentUser->hash,
                &ctx->entryCount, &crypto->iv, &crypto->ciphertext,
                &crypto->ciphertext_len) != EXIT_SUCCESS) {
      fprintf(stderr, "Failed to read vault data\n");
      return EXIT_FAILURE;
    }
    if (decryptData(crypto->ciphertext, crypto->ciphertext_len,
                    crypto->encryptionKey, crypto->iv, &crypto->plaintext,
                    crypto->plaintext_len) != EXIT_SUCCESS) {
      fprintf(stderr, "Decryption failed\n");
      return EXIT_FAILURE;
    }
    ctx->entries = unJsonEntries((char *)crypto->plaintext, &ctx->entryCount);

    if (!ctx->entries && ctx->entryCount > 0) {
      fprintf(stderr, "Failed to parse JSON entries\n");
      return EXIT_FAILURE;
    }
  }

  if (ctx->entryCount == 0) {
    printf("Vault is empty!\n");
    return EXIT_SUCCESS;
  }

  printf("Vault Entries:\n");
  for (int i = 0; i < ctx->entryCount; ++i) {
    entry *e = &ctx->entries[i];
    printf("Entry %d:\n", i + 1);
    printf("  Name:     %s\n", e->name);
    printf("  Username: %s\n", e->username);
    printf("  Password: %s\n", e->password);
    printf("  Website:  %s\n\n", e->website);
  }

  return EXIT_SUCCESS;
}

int editEntry(entry **entries, int entryCount, int index) {
  if (entries == NULL) {
    fprintf(stderr, "Error: entries pointer is NULL\n");
    return -1;
  }
  if (index < 0 || index >= entryCount) {
    fprintf(stderr, "Error: index %d out of bounds\n", index);
    return -1;
  }

  entry *e = entries[index];
  if (e == NULL) {
    fprintf(stderr, "Error: entry[%d] is NULL\n", index);
    return -1;
  }

  char buffer[MAX_WEBSITE_LEN];
  int ch;

  // Flush any leftover newline before the first fgets
  while ((ch = getchar()) != '\n' && ch != EOF) {
  }

  // Prompt for each field, read into the pre‐allocated buffer pointers
  printf("Enter name [%s]: ", e->name);
  if (fgets(buffer, MAX_NAME_LEN, stdin)) {
    buffer[strcspn(buffer, "\r\n")] = '\0';
    if (buffer[0] != '\0') {
      strncpy(e->name, buffer, MAX_NAME_LEN - 1);
      e->name[MAX_NAME_LEN - 1] = '\0';
    }
  } else {
    fprintf(stderr, "Error reading name\n");
    return -1;
  }

  printf("Enter username [%s]: ", e->username);
  if (fgets(buffer, MAX_USERNAME_LEN, stdin)) {
    buffer[strcspn(buffer, "\r\n")] = '\0';
    if (buffer[0] != '\0') {
      strncpy(e->username, buffer, MAX_USERNAME_LEN - 1);
      e->username[MAX_USERNAME_LEN - 1] = '\0';
    }
  } else {
    fprintf(stderr, "Error reading username\n");
    return -1;
  }

  printf("Enter password [%s]: ", e->password);
  if (fgets(buffer, MAX_PASSWORD_LEN, stdin)) {
    buffer[strcspn(buffer, "\r\n")] = '\0';
    if (buffer[0] != '\0') {
      strncpy(e->password, buffer, MAX_PASSWORD_LEN - 1);
      e->password[MAX_PASSWORD_LEN - 1] = '\0';
    }
  } else {
    fprintf(stderr, "Error reading password\n");
    return -1;
  }

  printf("Enter website [%s]: ", e->website);
  if (fgets(buffer, MAX_WEBSITE_LEN, stdin)) {
    buffer[strcspn(buffer, "\r\n")] = '\0';
    if (buffer[0] != '\0') {
      strncpy(e->website, buffer, MAX_WEBSITE_LEN - 1);
      e->website[MAX_WEBSITE_LEN - 1] = '\0';
    }
  } else {
    fprintf(stderr, "Error reading website\n");
    return -1;
  }

  return 0;
}
int searchEntry(entry *entries, int entryCount) {
  char searchTerm[MAX_NAME_LEN];
  int editEntr = 0;

  printf("Enter the term to search vault: ");
  if (!fgets(searchTerm, sizeof(searchTerm), stdin)) {
    fprintf(stderr, "Failed to read searchTerm\n");
    return EXIT_FAILURE;
  }
  // Remove trailing newline character
  searchTerm[strcspn(searchTerm, "\n")] = '\0';

  printf("Results:\n");
  int found = 0;
  for (int i = 0; i < entryCount; i++) {
    if ((entries[i].name && strstr(entries[i].name, searchTerm)) ||
        (entries[i].username && strstr(entries[i].username, searchTerm)) ||
        (entries[i].website && strstr(entries[i].website, searchTerm)) ||
        (entries[i].password && strstr(entries[i].password, searchTerm))) {
      printf("\t%d:\n", i + 1);
      printf("\t\tName: %s\n", entries[i].name ? entries[i].name : "N/A");
      printf("\t\tWebsite: %s\n",
             entries[i].website ? entries[i].website : "N/A");
      printf("\t\tUsername: %s\n",
             entries[i].username ? entries[i].username : "N/A");
      printf("\t\tPassword: %s\n",
             entries[i].password ? entries[i].password : "N/A");
      found = 1;
    }
  }

  if (!found) {
    printf("No matching entries found.\n");
    return EXIT_SUCCESS;
  }

  printf(
      "To edit an entry, please enter its index number (0 to exit search): ");
  char input[10];
  if (!fgets(input, sizeof(input), stdin)) {
    fprintf(stderr, "Failed to read input\n");
    return EXIT_FAILURE;
  }
  editEntr = atoi(input);
  if (editEntr < 0 || editEntr > entryCount) {
    fprintf(stderr, "Invalid index entered.\n");
    return EXIT_FAILURE;
  }
  if (editEntr == 0) {
    return EXIT_SUCCESS;
  }

  // Adjust index to match array indexing
  // *entries = *editEntry(entries, entryCount, editEntr - 1);

  return EXIT_SUCCESS;
}
