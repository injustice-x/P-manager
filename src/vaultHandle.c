#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_LEN 100
#define MAX_USERNAME_LEN 100
#define MAX_PASSWORD_LEN 100
#define MAX_WEBSITE_LEN 100

// Helper to flush leftover newline from stdin
static void flush_stdin(void) {
  int c;
  while ((c = getchar()) != EOF && c != '\n')
    ;
}

/**
 * showVault: Decrypts the stored ciphertext, parses JSON entries, and prints
 * them.
 */
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
                crypto->ciphertext_len) != EXIT_SUCCESS) {
      fprintf(stderr, "Failed to read vault data\n");
      return EXIT_FAILURE;
    }

    if (decryptData(crypto->ciphertext, *crypto->ciphertext_len,
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

/**
 * addEntry: Prompts for a new entry, appends it, re‑encrypts, and writes back.
 */
int addEntry(passwordManagerContext *globalContext) {
  if (!globalContext || !globalContext->currentUser ||
      !globalContext->currentUser->currentContext) {
    fprintf(stderr, "Invalid global context\n");
    return EXIT_FAILURE;
  }

  userContext *context = globalContext->currentUser->currentContext;
  cryptoContext *crypto = context->crypto;

  // Expand entries array
  int newSize = context->entryCount + 1;
  entry *tmp = realloc(context->entries, newSize * sizeof(entry));
  if (!tmp) {
    perror("Memory reallocation failed");
    return EXIT_FAILURE;
  }
  context->entries = tmp;
  entry *e = &context->entries[context->entryCount];

  // Allocate fields
  e->name = malloc(MAX_NAME_LEN);
  e->username = malloc(MAX_USERNAME_LEN);
  e->password = malloc(MAX_PASSWORD_LEN);
  e->website = malloc(MAX_WEBSITE_LEN);
  if (!e->name || !e->username || !e->password || !e->website) {
    perror("Allocation failed for new entry");
    free(e->name);
    free(e->username);
    free(e->password);
    free(e->website);
    return EXIT_FAILURE;
  }

  // **No flush_stdin() here**—main() has already cleared the '\n'
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

  context->entryCount++;

  // Serialize to JSON
  free(crypto->plaintext);
  crypto->plaintext = (unsigned char *)jsonEntries(
      context->entries, globalContext->username, context->entryCount);
  if (!crypto->plaintext) {
    fprintf(stderr, "Failed to serialize entries to JSON\n");
    return EXIT_FAILURE;
  }

  // **Fix: store length into the int, not pointer**
  *(crypto->plaintext_len) = (int)strlen((char *)crypto->plaintext);

  // Encrypt updated plaintext
  free(crypto->ciphertext);
  if (encryptData(crypto->plaintext, (crypto->plaintext_len),
                  crypto->encryptionKey, &crypto->iv, &crypto->ciphertext,
                  crypto->ciphertext_len) < 0) {
    fprintf(stderr, "Encryption failed\n");
    return EXIT_FAILURE;
  }

  // Write out everything
  if (writeData(globalContext->filePath, globalContext->currentUser->hash,
                context->entryCount, crypto->iv, crypto->ciphertext,
                (crypto->ciphertext_len)) != EXIT_SUCCESS) {
    fprintf(stderr, "Failed to write data to file\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;

fail_input:
  fprintf(stderr, "Error reading input\n");
  free(e->name);
  free(e->username);
  free(e->password);
  free(e->website);
  return EXIT_FAILURE;
}
