#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024

int writeHashes(hashes *hash, const char *dataFilePath, int entryCount) {
  if (hash == NULL || dataFilePath == NULL) {
    fprintf(stderr, "Invalid input to writeHashes\n");
    return EXIT_FAILURE;
  }

  FILE *f = fopen(dataFilePath, "w");
  if (f == NULL) {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  // Write the username hash on the first line.
  if (fputs((const char *)hash->usernameHash, f) == EOF) {
    perror("Error writing username hash");
    fclose(f);
    return EXIT_FAILURE;
  }
  if (fputc('\n', f) == EOF) {
    perror("Error writing newline after username hash");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Write the password hash on the second line.
  if (fputs((const char *)hash->passwordHash, f) == EOF) {
    perror("Error writing password hash");
    fclose(f);
    return EXIT_FAILURE;
  }
  if (fputc('\n', f) == EOF) {
    perror("Error writing newline after password hash");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Write the entry count on the third line.
  if (fprintf(f, "%d\n", entryCount) < 0) {
    perror("Error writing entry count");
    fclose(f);
    return EXIT_FAILURE;
  }

  fclose(f);
  return EXIT_SUCCESS;
}

hashes *getHashes(const char *dataFilePath) {
  if (dataFilePath == NULL) {
    fprintf(stderr, "Invalid input to getHashes\n");
    return NULL;
  }

  FILE *f = fopen(dataFilePath, "r");
  if (f == NULL) {
    perror("Error opening file");
    return NULL;
  }

  hashes *result = malloc(sizeof(hashes));
  if (result == NULL) {
    perror("Error allocating memory for hashes");
    fclose(f);
    return NULL;
  }
  result->usernameHash = NULL;
  result->passwordHash = NULL;

  char buffer[MAX_LINE_LENGTH];

  // Read the username hash from the first line.
  if (fgets(buffer, MAX_LINE_LENGTH, f) == NULL) {
    perror("Error reading username hash");
    free(result);
    fclose(f);
    return NULL;
  }
  buffer[strcspn(buffer, "\n")] = '\0';
  result->usernameHash = (unsigned char *)strdup(buffer);
  if (result->usernameHash == NULL) {
    perror("Error allocating memory for usernameHash");
    free(result);
    fclose(f);
    return NULL;
  }

  // Read the password hash from the second line.
  if (fgets(buffer, MAX_LINE_LENGTH, f) == NULL) {
    perror("Error reading password hash");
    free(result->usernameHash);
    free(result);
    fclose(f);
    return NULL;
  }
  buffer[strcspn(buffer, "\n")] = '\0';
  result->passwordHash = (unsigned char *)strdup(buffer);
  if (result->passwordHash == NULL) {
    perror("Error allocating memory for passwordHash");
    free(result->usernameHash);
    free(result);
    fclose(f);
    return NULL;
  }

  fclose(f);
  return result;
}

int getEntryCount(const char *dataFilePath) {
  if (dataFilePath == NULL) {
    fprintf(stderr, "Invalid input to getEntryCount\n");
    return EXIT_FAILURE;
  }

  FILE *f = fopen(dataFilePath, "r");
  if (f == NULL) {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  char buffer[MAX_LINE_LENGTH];
  int currentLine = 0;
  int entryCount = 0;

  while (fgets(buffer, sizeof(buffer), f) != NULL) {
    currentLine++;
    if (currentLine == 3) {
      // 'buffer' now contains the content of the third line.
      buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character
      entryCount = atoi(buffer);
      break;
    }
  }

  if (currentLine < 3) {
    fprintf(stderr, "File does not contain enough lines to read entry count\n");
    fclose(f);
    return EXIT_FAILURE;
  }

  fclose(f);
  return entryCount;
}

int writeData(unsigned char *encrypted, const char *dataFilePath,
              int entryCount) {
  FILE *f = fopen(dataFilePath, "r+");
  if (f == NULL) {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  // Move to the end of the third line
  char buffer[MAX_LINE_LENGTH];
  for (int i = 0; i < 3; i++) {
    if (fgets(buffer, MAX_LINE_LENGTH, f) == NULL) {
      perror("Error reading file");
      fclose(f);
      return EXIT_FAILURE;
    }
  }

  // Append the encrypted data from the fourth line
  if (fputs((const char *)encrypted, f) == EOF) {
    perror("Error writing encrypted data");
    fclose(f);
    return EXIT_FAILURE;
  }

  fclose(f);
  return EXIT_SUCCESS;
}
