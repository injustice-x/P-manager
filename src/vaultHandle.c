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

entry *editEntry(entry *entries, int entryCount, int index) {
  entry *temp = malloc(sizeof(entry) * entryCount);

  for (int i = 0; i < entryCount; i++) {

    temp[i].name = malloc(MAX_NAME_LEN);
    temp[i].username = malloc(MAX_USERNAME_LEN);
    temp[i].password = malloc(MAX_PASSWORD_LEN);
    temp[i].website = malloc(MAX_WEBSITE_LEN);

    if (i == index) {
      printf("old entry data:\n");
      printf("\tname:");
      if (!fgets(temp[i].name, MAX_NAME_LEN, stdin)) {
        fprintf(stderr, "Error reading name\n");
        goto fail;
      }
      temp[i].name[strcspn(temp[i].name, "\n")] = '\0';

      printf("\twebsite:");
      if (!fgets(temp[i].website, MAX_WEBSITE_LEN, stdin)) {
        fprintf(stderr, "Error reading website\n");
        goto fail;
      }
      temp[i].website[strcspn(temp[i].website, "\n")] = '\0';

      printf("\tusername:");
      if (!fgets(temp[i].username, MAX_USERNAME_LEN, stdin)) {
        fprintf(stderr, "Error reading username\n");
        goto fail;
      }
      temp[i].username[strcspn(temp[i].username, "\n")] = '\0';

      printf("\tpassword:");
      if (!fgets(temp[i].password, MAX_PASSWORD_LEN, stdin)) {
        fprintf(stderr, "Error reading password\n");
        goto fail;
      }
      temp[i].password[strcspn(temp[i].password, "\n")] = '\0';
    }

    else {
      temp[i].name = entries[i].name;
      temp[i].username = entries[i].username;
      temp[i].password = entries[i].password;
      temp[i].website = entries[i].website;
    }
  }
  return temp;

fail:
  fprintf(stderr, "coudn't read input\n");
  return entries;
}
