#include "../include/context.h"
#include <string.h>

passwordManagerContext *passwordManagerInit(const char *usersFilePath) {
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
        free(globalContext->users);
        if (!globalContext->currentUser) {
          free(globalContext->currentUser);
        }
        free(globalContext);
        return NULL;
      }
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
  for (size_t i = 0; i < globalContext->userCount; i++) {
    free(globalContext->users->usernameHash);
    free(globalContext->users->passwordHash);
  }

  free(globalContext->users);
  free(globalContext);
  globalContext = NULL;
  return;
};

void currentUserFree(userTable *currentUser) {

  for (size_t i = 0; i < globalContext->users->userData->entryCount; i++) {
    free(currentUser->userData->entries[i].website);
    free(currentUser->userData->entries[i].password);
    free(currentUser->userData->entries[i].username);
  }
}
