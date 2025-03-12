#include "../include/context.h"

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
  globalContext->currentUser->hash = malloc(sizeof(hashes));

  if (globalContext->currentUser == NULL) {
    free(globalContext->currentUser);
    free(globalContext);
    return NULL;
  }

  return globalContext;
}

void freeGlobalContext(passwordManagerContext *globalContext) {
  free(globalContext->currentUser->currentContext);
  free(globalContext->currentUser->hash);

  free(globalContext->currentUser);
  free(globalContext);
}
