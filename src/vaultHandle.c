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
  entry *oldEntries = ctx->entries;
  int oldCount = ctx->entryCount;

  // 1) Safely expand entries array
  entry *newEntries = realloc(ctx->entries, (oldCount + 1) * sizeof(entry));
  if (!newEntries) {
    perror("Realloc failed");
    return EXIT_FAILURE; // original entries intact
                         // :contentReference[oaicite:5]{index=5}
  }
  ctx->entries = newEntries;
  entry *e = &ctx->entries[oldCount];

  // 2) Allocate fields for new entry
  e->name = malloc(MAX_NAME_LEN);
  e->username = malloc(MAX_USERNAME_LEN);
  e->password = malloc(MAX_PASSWORD_LEN);
  e->website = malloc(MAX_WEBSITE_LEN);
  if (!e->name || !e->username || !e->password || !e->website) {
    perror("Allocation failed");
    goto cleanup_alloc; // free nothing yet, rollback below
                        // :contentReference[oaicite:6]{index=6}
  }

  // 3) Read user input
  printf("Enter name: ");
  if (!fgets(e->name, MAX_NAME_LEN, stdin))
    goto fail_input;
  e->name[strcspn(e->name, "\n")] = '\0';

  printf("Enter username: ");
  if (!fgets(e->username, MAX_USERNAME_LEN, stdin))
    goto fail_input;
  e->username[strcspn(e->username, "\n")] = '\0';

  printf("Enter password: ");
  if (!fgets(e->password, MAX_PASSWORD_LEN, stdin))
    goto fail_input;
  e->password[strcspn(e->password, "\n")] = '\0';

  printf("Enter website: ");
  if (!fgets(e->website, MAX_WEBSITE_LEN, stdin))
    goto fail_input;
  e->website[strcspn(e->website, "\n")] = '\0';
  // 4) Serialize to JSON plaintext
  unsigned char *json = (unsigned char *)jsonEntries(
      ctx->entries, globalContext->username, oldCount + 1);
  if (!json) {
    fprintf(stderr, "JSON serialization failed\n");
    goto cleanup_fields;
  }
  free(crypto->plaintext);
  crypto->plaintext = json;
  *crypto->plaintext_len =
      strlen((char *)json); // safe because null-terminated
                            // :contentReference[oaicite:8]{index=8}

  // 5) Encrypt and securely erase plaintext
  if (encryptData(crypto->plaintext, crypto->plaintext_len,
                  crypto->encryptionKey, &crypto->iv, &crypto->ciphertext,
                  &crypto->ciphertext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Encryption failed\n");
    goto cleanup_json;
  }
  explicit_bzero(
      crypto->plaintext,
      *crypto->plaintext_len); // prevents residual data
                               // :contentReference[oaicite:9]{index=9}

  // 6) Write out hashes, count, IV, and ciphertext
  if (writeData(globalContext->filePath, globalContext->currentUser->hash,
                oldCount + 1, crypto->iv, crypto->ciphertext,
                &crypto->ciphertext_len) != EXIT_SUCCESS) {
    fprintf(stderr, "Write failed\n");
    goto cleanup_cipher;
  }

  ctx->entryCount++;
  return EXIT_SUCCESS;

// Cleanup on write failure
cleanup_cipher:
  free(crypto->ciphertext);

// Cleanup on serialization or encryption failure
cleanup_json:
  free(crypto->plaintext);

// Cleanup on input or allocation failure for fields
cleanup_fields:
  free(e->name);
  free(e->username);
  explicit_bzero(e->password, strlen(e->password));
  free(e->password);
  free(e->website);

// Roll back array expansion
cleanup_alloc:
  ctx->entries = oldEntries;
  return EXIT_FAILURE;
fail_input:
  fprintf(stderr, "Error reading input\n");
  free(e->name);
  free(e->username);
  free(e->password);
  free(e->website);
  return EXIT_FAILURE;
}

int showVault(passwordManagerContext *globalContext) {
  if (!globalContext || !globalContext->currentUser ||
      !globalContext->currentUser->currentContext) {
    fprintf(stderr, "Invalid global context\n");
    return EXIT_FAILURE;
  }

  userContext *context = globalContext->currentUser->currentContext;
  cryptoContext *crypto = context->crypto;

  // Load & decrypt only once
  if (context->entries == NULL) {
    if (getData(globalContext->filePath, globalContext->currentUser->hash,
                &context->entryCount, &crypto->iv, &crypto->ciphertext,
                &crypto->ciphertext_len) != EXIT_SUCCESS) {
      fprintf(stderr, "Failed to read vault data\n");
      return EXIT_FAILURE;
    }

    if (decryptData(crypto->ciphertext, crypto->ciphertext_len,
                    crypto->encryptionKey, // use encryptionKey field
                    crypto->iv, &crypto->plaintext,
                    crypto->plaintext_len) != EXIT_SUCCESS) {
      fprintf(stderr, "Decryption failed\n");
      free(crypto->ciphertext);
      return EXIT_FAILURE;
    }

    context->entries =
        unJsonEntries((char *)crypto->plaintext, &context->entryCount);
    if (!context->entries && context->entryCount > 0) {
      fprintf(stderr, "Failed to parse JSON entries\n");
      return EXIT_FAILURE;
    }
  }

  if (context->entryCount == 0) {
    printf("Vault is empty!\n");
    return EXIT_SUCCESS;
  }

  printf("Vault Entries:\n");
  for (int i = 0; i < context->entryCount; ++i) {
    entry *e = &context->entries[i];
    printf("Entry %d:\n", i + 1);
    printf("  Name:     %s\n", e->name);
    printf("  Username: %s\n", e->username);
    printf("  Password: %s\n", e->password);
    printf("  Website:  %s\n\n", e->website);
  }

  return EXIT_SUCCESS;
}
