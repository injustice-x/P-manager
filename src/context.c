#include "../include/context.h"
#include <stdlib.h>

passwordManagerContext *initPasswordManagerContext(const char *dataFilePath) {
  if (dataFilePath == NULL) {
    return NULL;
  }

  passwordManagerContext *globalContext =
      malloc(sizeof(passwordManagerContext));
  if (globalContext == NULL) {
    return NULL;
  }
  globalContext->filePath = dataFilePath;

  globalContext->currentUser = malloc(sizeof(user));
  if (globalContext->currentUser == NULL) {
    free(globalContext);
    return NULL;
  }

  globalContext->currentUser->hash = malloc(sizeof(hashes));
  if (globalContext->currentUser->hash == NULL) {
    free(globalContext->currentUser);
    free(globalContext);
    return NULL;
  }

  globalContext->currentUser->currentContext = malloc(sizeof(userContext));
  if (globalContext->currentUser->currentContext == NULL) {
    free(globalContext->currentUser->hash);
    free(globalContext->currentUser);
    free(globalContext);
    return NULL;
  }

  globalContext->currentUser->currentContext->crypto =
      malloc(sizeof(cryptoContext));
  if (globalContext->currentUser->currentContext->crypto == NULL) {
    free(globalContext->currentUser->currentContext);
    free(globalContext->currentUser->hash);
    free(globalContext->currentUser);
    free(globalContext);
    return NULL;
  }

  /* Optionally initialize pointers in cryptoContext to NULL */
  globalContext->currentUser->currentContext->crypto->encryptionKey = NULL;
  globalContext->currentUser->currentContext->crypto->iv = NULL;
  globalContext->currentUser->currentContext->crypto->plaintext = NULL;
  globalContext->currentUser->currentContext->crypto->ciphertext = NULL;
  globalContext->currentUser->currentContext->crypto->plaintext_len = NULL;
  globalContext->currentUser->currentContext->crypto->len = NULL;

  /* Initialize entry count and entries pointer */
  globalContext->currentUser->currentContext->entryCount = 0;
  globalContext->currentUser->currentContext->entries = NULL;
  globalContext->currentUser->currentContext->crypto->plaintext_len =
      malloc(sizeof(int));
  return globalContext;
}

int loadEntries(passwordManagerContext *globalContext) {

  userContext *ctx = globalContext->currentUser->currentContext;
  cryptoContext *crypto = ctx->crypto;
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

  return EXIT_SUCCESS;
}

void freeGlobalContext(passwordManagerContext *globalContext) {
  if (globalContext == NULL)
    return;

  if (globalContext->currentUser) {
    if (globalContext->currentUser->hash) {
      free(globalContext->currentUser->hash->passwordHash);
      free(globalContext->currentUser->hash->usernameHash);
      free(globalContext->currentUser->hash);
    }

    if (globalContext->currentUser->currentContext) {
      if (globalContext->currentUser->currentContext->crypto) {
        free(globalContext->currentUser->currentContext->crypto->encryptionKey);
        free(globalContext->currentUser->currentContext->crypto->iv);
        free(globalContext->currentUser->currentContext->crypto->ciphertext);
        free(globalContext->currentUser->currentContext->crypto->plaintext_len);
        free(globalContext->currentUser->currentContext->crypto->len);
        free(globalContext->currentUser->currentContext->crypto->plaintext);
        free(globalContext->currentUser->currentContext->crypto);
      }

      if (globalContext->currentUser->currentContext->entries) {
        for (int i = 0;
             i < globalContext->currentUser->currentContext->entryCount; i++) {
          free(globalContext->currentUser->currentContext->entries[i].name);
          free(globalContext->currentUser->currentContext->entries[i].username);
          free(globalContext->currentUser->currentContext->entries[i].password);
          free(globalContext->currentUser->currentContext->entries[i].website);
        }
        free(globalContext->currentUser->currentContext->entries);
      }
      free(globalContext->currentUser->currentContext);
    }
    free(globalContext->currentUser);
  }
  free(globalContext);
}
