#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_SIZE 50

int main(int argc, char *argv[]) {
  if (argc == 1) {
    fprintf(stderr, "Usage: %s -f <filepath>\n", argv[0]);

    return 0;
  }
  int opt;

  char *filePath = NULL; // Use non-const so we can free it later

  // Process command line options using getopt
  while ((opt = getopt(argc, argv, "f:")) != -1) {
    switch (opt) {
    case 'f':
      filePath = strdup(optarg);
      if (filePath == NULL) {
        perror("Error duplicating file path");
        free(filePath);
        exit(EXIT_FAILURE);
      }
      break;
    default: /* '?' */
      fprintf(stderr, "Usage: %s -f <filepath>\n", argv[0]);
      free(filePath);
      exit(EXIT_FAILURE);
    }
  }
  const char *dataFilePath = strdup(filePath);
  // Ensure that dataFilePath was provided
  if (dataFilePath == NULL) {
    fprintf(stderr, "Error: file path not provided. Use -f <value>\n");
    exit(EXIT_FAILURE);
  }

  // Initialize global context
  passwordManagerContext *globalContext =
      initPasswordManagerContext(dataFilePath);
  if (globalContext == NULL) {
    fprintf(stderr, "Failed to initialize password manager context\n");
    free(filePath);
    exit(EXIT_FAILURE);
  }
  // Check if the file exists. If it doesn't, call addUser.
  if (access(dataFilePath, F_OK) != 0) {
    printf("File doesn't exist\n");
    if (addUser(globalContext) != 0) {
      fprintf(stderr, "Error adding user\n");
    }
  } else {
    hashes *hash;
    if (getUser(globalContext) == 1) {
      printf("Couldnt get User from File");
      return 0;
    }
  }

  int choice = 0;
  while (choice == 0) {
    printf("Select from below:\n");
    printf("1.add new item\n");
    printf("2.view vault\n");
    printf("3.search vault\n");
    printf("0.exit\n");

    scanf("%d", &choice);

    switch (choice) {
    case 1: {
      globalContext->currentUser->currentContext->entries =
          malloc(sizeof(entry));
      if (!globalContext->currentUser->currentContext->entries) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(1);
      }
      entry *testJson = globalContext->currentUser->currentContext->entries;
      globalContext->currentUser->currentContext->entryCount = 1;
      testJson->name = "name1";
      printf("enter username: ");
      testJson->username = "username1"; // Replace with user input if needed
      printf("enter password: ");
      testJson->password = "password1"; // Replace with user input if needed
      printf("enter website: ");
      testJson->website = "website1"; // Replace with user input if needed

      encryptData(globalContext);
      decryptData(globalContext);
      break;
    }
    case 2:
      printf("choice 2");
      int x = getEntryCount(globalContext->filePath);

      break;
    }
  }

  // Clean up
  freeGlobalContext(globalContext);
  free(filePath);

  return EXIT_SUCCESS;
}
