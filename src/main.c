#include "../include/context.h"
#include <stdio.h>
#include <unistd.h>
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
  }

  // Clean up
  freeGlobalContext(globalContext);
  free(filePath);

  return EXIT_SUCCESS;
}
