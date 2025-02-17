#include "../include/context.h"

passwordManagerContext *globalContext = NULL;

int passwordManagerInit(const char *dataFilePath, const char *userFilePath) {
  if (globalContext != NULL)
    return -1;
  globalContext = malloc(sizeof(passwordManagerContext));
  if (!globalContext)
    return -1;
  /*initialize all fields to zero*/
  memset(globalContext, 0, sizeof(passwordManagerContext));

  if (dataFilePath) {
    globalContext->user->userData->dataFilePath = strdup(dataFilePath);
    if (!globalContext->user->userData->dataFilePath) {
      free(globalContext);
      globalContext = NULL;
      return -1;
    }
  }
  return 0;
  if (userFilePath) {
    globalContext->userFilePath = strdup(userFilePath);
    if (!globalContext->userFilePath) {
      free(globalContext);
      globalContext = NULL;
      return -1;
    }
  }
  return 0;
};

void passwordManagerFree(void) {
  if (globalContext != NULL)
    return;
  free(globalContext->dataFilePath);
  free(globalContext->userFilePath);

  /*free all password entries*/
  for (size_t i = 0; i < globalContext->entryCount; i++) {
    free(globalContext->entries[i].website);
    free(globalContext->entries[i].password);
    free(globalContext->entries[i].username);
  }
  for (size_t i = 0; i < globalContext->userCount; i++) {
    free(globalContext->users->usernameHash);
    free(globalContext->users->passwordHash);
  }
  free(globalContext->entries);
  free(globalContext->users);
  free(globalContext->encryptionKey);
  free(globalContext);
  globalContext = NULL;
}
