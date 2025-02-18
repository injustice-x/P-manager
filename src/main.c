#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 256

int main(int argc, char *argv[]) {
  char name[MAX_INPUT];      // Allocate buffer for the user's name
  char mPassword[MAX_INPUT]; // Allocate buffer for the master password

  printf("Enter the name of the user:\n");
  if (fgets(name, sizeof(name), stdin) != NULL) {
    // Remove the trailing newline character, if present
    size_t len = strlen(name);
    if (len > 0 && name[len - 1] == '\n') {
      name[len - 1] = '\0';
    }
  } else {
    fprintf(stderr, "Error reading user name.\n");
    return 1;
  }

  printf("Enter master password:\n");
  if (fgets(mPassword, sizeof(mPassword), stdin) != NULL) {
    // Remove the trailing newline character, if present
    size_t len = strlen(mPassword);
    if (len > 0 && mPassword[len - 1] == '\n') {
      mPassword[len - 1] = '\0';
    }
  } else {
    fprintf(stderr, "Error reading master password.\n");
    return 1;
  }

  // Call addUser with the provided name and password.
  // Note: addUser should be implemented to handle these inputs appropriately.
  if (addUser(name, mPassword) != 0) {
    fprintf(stderr, "Failed to add user.\n");
    return 1;
  }

  return 0;
}
