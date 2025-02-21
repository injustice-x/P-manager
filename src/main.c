#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256

// promptAddPassword:
// Prompts the user to input details for a new password entry (website, entry
// username, and entry password) and then calls addPassword() to add this entry
// to the currently authenticated user.
void promptAddPassword(void) {
  char website[MAX_INPUT];
  char entryUsername[MAX_INPUT];
  char entryPassword[MAX_INPUT];

  printf("\n=== Add Password Entry ===\n");
  printf("Enter website: ");
  if (!fgets(website, sizeof(website), stdin)) {
    fprintf(stderr, "Error reading website.\n");
    return;
  }
  website[strcspn(website, "\n")] = '\0';

  printf("Enter entry username: ");
  if (!fgets(entryUsername, sizeof(entryUsername), stdin)) {
    fprintf(stderr, "Error reading entry username.\n");
    return;
  }
  entryUsername[strcspn(entryUsername, "\n")] = '\0';

  printf("Enter entry password: ");
  if (!fgets(entryPassword, sizeof(entryPassword), stdin)) {
    fprintf(stderr, "Error reading entry password.\n");
    return;
  }
  entryPassword[strcspn(entryPassword, "\n")] = '\0';

  // Prepare a temporary userData structure to hold one new entry.
  userData newData = {0};
  newData.entryCount = 1;
  newData.entries = malloc(sizeof(passwordEntry));
  if (!newData.entries) {
    fprintf(stderr, "Memory allocation error for password entry.\n");
    return;
  }
  newData.entries[0].website = strdup(website);
  newData.entries[0].username = strdup(entryUsername);
  newData.entries[0].password = strdup(entryPassword);
  if (!newData.entries[0].website || !newData.entries[0].username ||
      !newData.entries[0].password) {
    fprintf(stderr, "Memory allocation error for entry fields.\n");
    free(newData.entries[0].website);
    free(newData.entries[0].username);
    free(newData.entries[0].password);
    free(newData.entries);
    return;
  }

  // Call addPassword() to append the new entry to the current user's data.
  if (addPassword(globalContext->currentUser, newData) == 0) {
    printf("Password entry added successfully.\n");
  } else {
    printf("Failed to add password entry.\n");
  }

  // Free the temporary newData copy; the addPassword function is assumed to
  // copy the strings.
  free(newData.entries[0].website);
  free(newData.entries[0].username);
  free(newData.entries[0].password);
  free(newData.entries);
}

int main(void) {
  char command[MAX_INPUT];

  // Initialize the global password manager context (using a sample users file).
  globalContext = passwordManagerInit("users.txt");
  if (!globalContext) {
    fprintf(stderr, "Failed to initialize password manager context.\n");
    return EXIT_FAILURE;
  }

  // Prompt the user to choose between signup and login.
  while (1) {
    printf("\nEnter command (signup, login, exit): ");
    if (!fgets(command, sizeof(command), stdin))
      break;
    command[strcspn(command, "\n")] = '\0';

    if (strcmp(command, "signup") == 0) {
      signup();
      break;
    } else if (strcmp(command, "login") == 0) {
      login();
      break;
    } else if (strcmp(command, "exit") == 0) {
      passwordManagerFree(globalContext);
      globalContext = NULL;
      return EXIT_SUCCESS;
    } else {
      printf("Unknown command. Please enter 'signup', 'login', or 'exit'.\n");
    }
  }

  // Check that a user is now present in the global context.
  if (!globalContext->currentUser) {
    printf("No user context available. Exiting.\n");
    passwordManagerFree(globalContext);
    globalContext = NULL;
    return EXIT_FAILURE;
  }

  // Ask the user whether to add a new password entry.
  printf("\nDo you want to add a new password entry? (yes/no): ");
  if (fgets(command, sizeof(command), stdin)) {
    command[strcspn(command, "\n")] = '\0';
    if (strcmp(command, "yes") == 0) {
      promptAddPassword();
    } else {
      printf("No new password entry added.\n");
    }
  } else {
    fprintf(stderr, "Error reading input.\n");
  }

  // Optionally, write some data to a file to verify file I/O.
  char buffer[512];
  snprintf(buffer, sizeof(buffer), "usernameHash: %s\npasswordHash: %s\n",
           globalContext->currentUser->usernameHash,
           globalContext->currentUser->passwordHash);
  if (writeFile("user_data.txt", buffer) == 0) {
    printf("User data written to file.\n");
  } else {
    printf("Failed to write user data to file.\n");
  }

  // Cleanup.
  passwordManagerFree(globalContext);
  globalContext = NULL;
  return EXIT_SUCCESS;
}
