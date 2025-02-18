#include "../include/context.h"
#include <string.h>

passwordManagerContext *globalContext = NULL;

passwordManagerContext *passwordManagerInit(const char *dataFilePath,
                                            const char *usersFilePath) {
  passwordManagerContext *globalContext =
      malloc(sizeof(passwordManagerContext));
  if (!globalContext) {
    return NULL;
  }
  memset(globalContext, 0, sizeof(passwordManagerContext));

  globalContext->userCount = 0;
  globalContext->users = NULL;

  if (usersFilePath) {
    globalContext->usersFilePath = strdup(usersFilePath);
    if (!globalContext->usersFilePath) {
      // Cleanup if duplication fails.
      if (globalContext->userCount > 0 && globalContext->users) {
        free(globalContext->users[0].userData->dataFilePath);
        free(globalContext->users[0].userData);
        free(globalContext->users);
      }
      free(globalContext);
      return NULL;
    }
  }
  return globalContext;
};

void passwordManagerFree(passwordManagerContext *globalContext) {
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
