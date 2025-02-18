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
    globalContext->users->userData->dataFilePath = strdup(dataFilePath);
    if (!globalContext->users->userData->dataFilePath) {
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
  free(globalContext->users->userData->dataFilePath);
  free(globalContext->usersFilePath);

  /*free all password entries*/
  for (size_t i = 0; i < globalContext->users->userData->entryCount; i++) {
    free(globalContext->users->userData->entries[i].website);
    free(globalContext->users->userData->entries[i].password);
    free(globalContext->users->userData->entries[i].username);
  }
  for (size_t i = 0; i < globalContext->userCount; i++) {
    free(globalContext->users->usernameHash);
    free(globalContext->users->passwordHash);
  }
  free(globalContext->users->userData->entries);
  free(globalContext->users->userData->encryptionKey);

  free(globalContext->users->passwordHash);
  free(globalContext->users->usernameHash);
  free(globalContext->users->userData);

  free(globalContext->users);
  free(globalContext);
  globalContext = NULL;
}
