#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024

int writeHashes(hashes *hash, const char *dataFilePath, int entryCount) {
  FILE *f = fopen(dataFilePath, "w");
  char buffer[10];
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

  // Write a newline character after the username hash.
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

  // Write a newline character after the password hash.
  if (fputc('\n', f) == EOF) {
    perror("Error writing newline after password hash");
    fclose(f);
    return EXIT_FAILURE;
  }

  sprintf(buffer, "%d", entryCount);
  if (fputs(buffer, f) == EOF) {
    perror("Error writing entry");
    fclose(f);
    return EXIT_FAILURE;
  }
  printf("done");

  fclose(f);
  return 0;
}

hashes *getHashes(const char *dataFilePath) {
  FILE *f = fopen(dataFilePath, "r");
  if (f == NULL) {
    perror("Error Opening File!!");
    return NULL;
  }

  hashes *result = malloc(sizeof(hashes));
  if (result == NULL) {
    perror("error allocating memory!!");
    fclose(f);
    return NULL;
  }
  result->usernameHash = NULL;
  result->passwordHash = NULL;

  char buffer[MAX_LINE_LENGTH];

  if (fgets(buffer, MAX_LINE_LENGTH, f) != NULL) {
    buffer[strcspn(buffer, "\n")] = '\0';
    result->usernameHash = (unsigned char *)strdup(buffer);
    if (result->usernameHash == NULL) {
      perror("memory allocation failed for usernameHash");
      fclose(f);
      free(result);
      return NULL;
    }
  } else {
    // First line not found.
    fclose(f);
    free(result);
    return NULL;
  }

  if (fgets(buffer, MAX_LINE_LENGTH, f) != NULL) {
    buffer[strcspn(buffer, "\n")] = '\0';
    result->passwordHash = (unsigned char *)strdup(buffer);
    if (result->passwordHash == NULL) {
      perror("memory allocation failed for usernameHash");
      fclose(f);
      free(result);
      return NULL;
    }
  } else {
    // second line not found
    fclose(f);
    free(result);
    return NULL;
  }

  fclose(f);
  return result;
}

int getEntryCount(const char *dataFilePath) {
  int currentLine = 0;
  int entryCount = 0;
  char line[MAX_LINE_LENGTH];

  FILE *f = fopen(dataFilePath, "r");
  if (f == NULL) {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  while (fgets(line, sizeof(line), f) != NULL) {
    currentLine++;
    if (currentLine == 3) {
      // 'line' now contains the content of the third line.
      printf("\nLine 3: %s", line);
      break;
    }
  }

  fclose(f);
  return entryCount;
}
