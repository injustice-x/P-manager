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
        free((void *)
                 globalContext->currentUser->currentContext->crypto->plaintext);
        free((void *)globalContext->currentUser->currentContext->crypto
                 ->ciphertext);
        free(globalContext->currentUser->currentContext->crypto->plaintext_len);
        free(globalContext->currentUser->currentContext->crypto->len);
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
