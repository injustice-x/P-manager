#include "../include/context.h"
#define MAX_INPUT 256
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
