#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256

// Helper: Convert a binary buffer to a hex string.
// (If already implemented elsewhere, you can remove this duplicate.)
static char *hexStringFromBytes(const unsigned char *bytes, unsigned int len) {
  char *hex = malloc(2 * len + 1);
  if (!hex)
    return NULL;
  for (unsigned int i = 0; i < len; i++) {
    sprintf(hex + i * 2, "%02x", bytes[i]);
  }
  hex[2 * len] = '\0';
  return hex;
}

// signup:
// Prompts the user for username and password, then calls addUser() to create a
// new user. The new user is stored in globalContext->currentUser.
void signup(void) {
  char username[MAX_INPUT];
  char password[MAX_INPUT];

  printf("=== Signup ===\n");
  printf("Enter username: ");
  if (!fgets(username, sizeof(username), stdin)) {
    fprintf(stderr, "Error reading username.\n");
    return;
  }
  // Remove the newline character.
  username[strcspn(username, "\n")] = '\0';

  printf("Enter password: ");
  if (!fgets(password, sizeof(password), stdin)) {
    fprintf(stderr, "Error reading password.\n");
    return;
  }
  password[strcspn(password, "\n")] = '\0';

  // Allocate a new userTable instance.
  userTable *newUser = calloc(1, sizeof(userTable));
  if (!newUser) {
    perror("calloc");
    return;
  }

  // Call addUser to compute and store hashes.
  if (addUser(newUser, username, password) != 0) {
    fprintf(stderr, "Failed to add user.\n");
    free(newUser);
    return;
  }

  globalContext->currentUser = newUser;
  printf("Signup successful.\n");
}

// login:
// Prompts the user for username and password and calls authUser() to verify
// credentials.
void login(void) {
  char username[MAX_INPUT];
  char password[MAX_INPUT];

  // Ensure there is a registered user.
  if (!globalContext || !globalContext->currentUser) {
    printf("No user registered. Please signup first.\n");
    return;
  }

  printf("=== Login ===\n");
  printf("Enter username: ");
  if (!fgets(username, sizeof(username), stdin)) {
    fprintf(stderr, "Error reading username.\n");
    return;
  }
  username[strcspn(username, "\n")] = '\0';

  printf("Enter password: ");
  if (!fgets(password, sizeof(password), stdin)) {
    fprintf(stderr, "Error reading password.\n");
    return;
  }
  password[strcspn(password, "\n")] = '\0';

  // The authUser function compares input credentials with stored values.
  userTable *authenticated = authUser(globalContext);
  if (authenticated) {
    printf("Login successful.\n");
  } else {
    printf("Login failed.\n");
  }
}

int main(void) {
  // Initialize the global context with the file path for users.
  globalContext = passwordManagerInit("users.txt");
  if (!globalContext) {
    fprintf(stderr, "Failed to initialize password manager context.\n");
    return EXIT_FAILURE;
  }

  char command[MAX_INPUT];
  while (1) {
    printf("\nEnter command (signup, login, exit): ");
    if (!fgets(command, sizeof(command), stdin))
      break;
    // Remove newline character.
    command[strcspn(command, "\n")] = '\0';

    if (strcmp(command, "signup") == 0) {
      signup();
    } else if (strcmp(command, "login") == 0) {
      login();
    } else if (strcmp(command, "exit") == 0) {
      break;
    } else {
      printf("Unknown command. Please enter 'signup', 'login', or 'exit'.\n");
    }
  }

  // Clean up.
  passwordManagerFree(globalContext);
  globalContext = NULL;
  return EXIT_SUCCESS;
}
