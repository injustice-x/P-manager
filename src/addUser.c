#include "../include/context.h"

int addUser(passwordManagerContext *globalContext, const char *username,
            const char *password) {

  if (globalContext == NULL) {
    fprintf(stderr, "Error: Global context is not initialized.\n");
    return -1;
  }
  if (username == NULL || password == NULL) {
    fprintf(stderr, "Error: Username or password is NULL.\n");
    return -1;
  }
  /*increase the user count and reallocate memory*/
  size_t newCount = globalContext->userCount++;
  userTable *temp = realloc(globalContext->users, newCount * sizeof(userTable));
  if (temp == NULL) {
    fprintf(stderr, "Error!! failed to reallocate memory");
    return -1;
  }

  globalContext->users = temp;

  /*get the pointer to newly allocated user*/
  userTable *newUser = &globalContext->users[newCount - 1];
  /*save the data*/
  newUser->usernameHash = strdup(username);
  newUser->passwordHash = strdup(password);

  if (newUser->passwordHash == NULL | newUser->usernameHash == NULL) {
    fprintf(stderr, "failed to save data");
    free(newUser->usernameHash);
    free(newUser->usernameHash);
    return -1;
  }

  memset(newUser->userData, 0, sizeof(userData));

  /*initialize some data*/
  newUser->userData->entryCount = 0;
  newUser->userData->isLoggedin = false;

  /*update the global context with new user*/
  globalContext->userCount = newCount;

  return 0;
}
