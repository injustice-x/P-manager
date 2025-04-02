#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for getopt, access

#define MAX_SIZE 50

int main(int argc, char *argv[]) {
  if (argc == 1) {
    fprintf(stderr, "Usage: %s -f <filepath>\n", argv[0]);
    return 0;
  }

  int opt;
  char *filePath = NULL; // non-const so it can be freed later

  // Process command-line options using getopt
  while ((opt = getopt(argc, argv, "f:")) != -1) {
    switch (opt) {
    case 'f':
      filePath = strdup(optarg);
      if (filePath == NULL) {
        perror("Error duplicating file path");
        exit(EXIT_FAILURE);
      }
      break;
    default: /* '?' */
      fprintf(stderr, "Usage: %s -f <filepath>\n", argv[0]);
      free(filePath);
      exit(EXIT_FAILURE);
    }
  }

  char *dataFilePath = strdup(filePath);
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
    free(dataFilePath);
    exit(EXIT_FAILURE);
  }

  // Check if the file exists. If it doesn't, call addUser.
  if (access(dataFilePath, F_OK) != 0) {
    printf("File doesn't exist\n");
    if (addUser(globalContext) != 0) {
      fprintf(stderr, "Error adding user\n");
    }
  } else {
    if (getUser(globalContext) == 1) {
      printf("Couldn't get User from File\n");
      freeGlobalContext(globalContext);
      free(filePath);
      free(dataFilePath);
      return 0;
    }
  }

  int choice = -1; // start with a non-zero value
  while (choice != 0) {
    printf("Select from below:\n");
    printf("1. Add new item\n");
    printf("2. View vault\n");
    printf("3. Search vault\n");
    printf("0. Exit\n");

    if (scanf("%d", &choice) != 1) {
      fprintf(stderr, "Invalid input. Please enter a number.\n");
      // Clear invalid input from buffer
      while (getchar() != '\n')
        ;
      continue;
    }
    // Clear the newline left in the buffer
    while (getchar() != '\n')
      ;

    switch (choice) {
    case 1:
      // Call addEntry to add a new item.
      if (addEntry(globalContext) != 0) {
        fprintf(stderr, "Failed to add new entry.\n");
      }
      break;
    case 2:
      // In this case, we encrypt, decrypt, then show the vault.
      if (encryptData(globalContext) < 0) {
        fprintf(stderr, "Encryption failed.\n");
      }
      if (decryptData(globalContext) < 0) { // assuming decryptString exists
        fprintf(stderr, "Decryption failed.\n");
      }
      showVault(globalContext);
      break;
    case 3:
      break;
    case 0:
      printf("Exiting...\n");
      break;
    default:
      printf("Invalid choice. Please try again.\n");
    }
  }

  // Clean up
  freeGlobalContext(globalContext);
  free(filePath);
  free(dataFilePath);

  return EXIT_SUCCESS;
}
