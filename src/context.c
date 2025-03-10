#include "../include/context.h"
#include <stdio.h>

passwordManagerContext *initPasswordManagerContext(const char *dataFilePath) {

  if (dataFilePath == NULL) {
    return NULL;
  }
  passwordManagerContext *globalContext;
  globalContext = malloc(sizeof(passwordManagerContext));

  if (globalContext == NULL) {
    free(globalContext);
    return NULL;
  }

  globalContext->filePath = dataFilePath;
  globalContext->currentUser = malloc(sizeof(user));

  if (globalContext->currentUser == NULL) {
    free(globalContext->currentUser);
    free(globalContext);
    return NULL;
  }

  return globalContext;
}

void freeGlobalContext(passwordManagerContext *globalContext) {
  free(globalContext->currentUser->currentContext);
  free(globalContext->currentUser->passwordHash);
  free(globalContext->currentUser->usernameHash);

  free(globalContext->currentUser);
  free(globalContext);
}
