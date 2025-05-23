#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define MAX_SIZE 50

int main(int argc, char *argv[]) {
  if (argc == 1) {
    fprintf(stderr, "Usage: %s -f <filepath>\n", argv[0]);
    return 0;
  }

  int opt;
  char *filePath = NULL;

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
      printf("\n");
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
    printf("3. Edit vault\n");
    printf("4. Search vault\n");
    printf("0. Exit\n");

    userContext *ctx = globalContext->currentUser->currentContext;
    cryptoContext *crypto = globalContext->currentUser->currentContext->crypto;

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
      if (addEntry(globalContext) != 0) {
        fprintf(stderr, "Failed to add new entry.\n");
      }
      break;
    case 2:
      showVault(globalContext);
      break;
    case 3:
      showVault(globalContext);
      int index;
      printf("Enter the index of the entry you want to edit:");
      scanf("%d", &index);
      if (index > ctx->entryCount) {
        printf("Index shouldn'c exceed the total entry count!!\nEnter again:");
        scanf("%d", &index);
      }
      ctx->entries = editEntry(ctx->entries, ctx->entryCount, index - 1);
      writeEntries(globalContext);
      break;
    case 4:
      loadEntries(globalContext);
      searchEntry(ctx->entries, ctx->entryCount);
      writeEntries(globalContext);
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
