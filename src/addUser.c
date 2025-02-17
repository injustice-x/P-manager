#include "../include/context.h"

/*
 * Adds a new user to the globalContext.
 * Returns 0 on success, -1 on failure.
 */
int addUser(const char *username, const char *password) {
  if (globalContext == NULL) {
    fprintf(stderr, "Error: Global context is not initialized.\n");
    return -1;
  }
  if (username == NULL || password == NULL) {
    fprintf(stderr, "Error: Username or password is NULL.\n");
    return -1;
  }

  // Increase the user count and reallocate the user array
  size_t newCount = globalContext->userCount + 1;
  userTable *temp = realloc(globalContext->user, newCount * sizeof(userTable));
  if (temp == NULL) {
    fprintf(stderr, "Error: Failed to reallocate memory for new user.\n");
    return -1;
  }
  globalContext->user = temp;

  // Get the pointer to the newly allocated userTable slot
  userTable *newUser = &globalContext->user[newCount - 1];

  // For demonstration purposes, we simply duplicate the strings.
  // In a real application, you should hash these values.
  newUser->usernameHash = strdup(username);
  newUser->passwordHash = strdup(password);
  if (newUser->usernameHash == NULL || newUser->passwordHash == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory for user credentials.\n");
    free(newUser->usernameHash);
    free(newUser->passwordHash);
    return -1;
  }

  // Allocate and initialize userData for the new user.
  newUser->userData = malloc(sizeof(userData));
  if (newUser->userData == NULL) {
    fprintf(stderr, "Error: Failed to allocate memory for user data.\n");
    free(newUser->usernameHash);
    free(newUser->passwordHash);
    return -1;
  }
  memset(newUser->userData, 0, sizeof(userData));

  // Optionally, you can set defaults for userData fields here.
  // For example, initialize entryCount to 0, set isLoggedin to false, etc.
  newUser->userData->entryCount = 0;
  newUser->userData->isLoggedin = false;

  // Update the global user count.
  globalContext->userCount = newCount;

  return 0;
}
