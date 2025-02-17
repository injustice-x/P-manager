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
    globalContext->usersFilePath = strdup(userFilePath);
    if (!globalContext->usersFilePath) {
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
  free(globalContext->user->userData->dataFilePath);
  free(globalContext->usersFilePath);

  /*free all password entries*/
  for (size_t i = 0; i < globalContext->user->userData->entryCount; i++) {
    free(globalContext->user->userData->entries[i].website);
    free(globalContext->user->userData->entries[i].password);
    free(globalContext->user->userData->entries[i].username);
  }
  for (size_t i = 0; i < globalContext->userCount; i++) {
    free(globalContext->user->usernameHash);
    free(globalContext->user->passwordHash);
  }
  free(globalContext->user->userData->entries);
  free(globalContext->user->userData->encryptionKey);

  free(globalContext->user->passwordHash);
  free(globalContext->user->usernameHash);
  free(globalContext->user->userData);

  free(globalContext->user);
  free(globalContext);
  globalContext = NULL;
}
