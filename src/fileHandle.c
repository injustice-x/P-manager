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

unsigned char *getData(const char *dataFilePath) {
  if (dataFilePath == NULL) {
    fprintf(stderr, "Invalid file path\n");
    return NULL;
  }

  FILE *fp = fopen(dataFilePath, "r");
  if (!fp) {
    perror("Error opening file");
    return NULL;
  }

  char buffer[1024];
  // Skip first three lines
  for (int i = 0; i < 3; i++) {
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
      // If file has less than three lines, nothing to read from 4th line onward
      fclose(fp);
      return NULL;
    }
  }

  // Get the current file position (i.e. start of fourth line)
  long offset = ftell(fp);
  if (offset == -1L) {
    perror("ftell failed");
    fclose(fp);
    return NULL;
  }

  // Seek to end to determine total file size
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek to end failed");
    fclose(fp);
    return NULL;
  }

  long fileSize = ftell(fp);
  if (fileSize == -1L) {
    perror("ftell failed");
    fclose(fp);
    return NULL;
  }

  // Calculate the size of data from 4th line onward
  long dataSize = fileSize - offset;
  if (dataSize <= 0) {
    fclose(fp);
    return NULL; // No data after the third line
  }

  // Allocate buffer for data plus a null terminator
  unsigned char *data = malloc(dataSize + 1);
  if (data == NULL) {
    perror("Memory allocation failed");
    fclose(fp);
    return NULL;
  }

  // Reposition to the offset where the 4th line starts
  if (fseek(fp, offset, SEEK_SET) != 0) {
    perror("fseek to offset failed");
    free(data);
    fclose(fp);
    return NULL;
  }

  // Read the remainder of the file into the buffer
  size_t bytesRead = fread(data, 1, dataSize, fp);
  data[bytesRead] = '\0'; // Null-terminate the data

  fclose(fp);
  return data;
}

// getEntryCount: Reads the 3rd line of the file, converts it to an int, and
// returns it.
int getEntryCount(const char *dataFilePath) {
  if (dataFilePath == NULL) {
    fprintf(stderr, "Invalid file path\n");
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
      // Remove any trailing newline character
      buffer[strcspn(buffer, "\n")] = '\0';
      entryCount = atoi(buffer);
      break;
    }
  }
  fclose(f);
  return entryCount;
}

// writeEntryCount: Writes the given entryCount to the 3rd line of the file,
// preserving the first two lines and any lines after the 3rd line.
int writeEntryCount(const char *dataFilePath, int entryCount) {
  if (dataFilePath == NULL) {
    fprintf(stderr, "Invalid file path\n");
    return EXIT_FAILURE;
  }

  FILE *f = fopen(dataFilePath, "r");
  if (f == NULL) {
    perror("Error opening file for reading");
    return EXIT_FAILURE;
  }

  // Read all lines into an array of strings
  char **lines = NULL;
  int lineCount = 0;
  char buffer[MAX_LINE_LENGTH];
  while (fgets(buffer, sizeof(buffer), f) != NULL) {
    lineCount++;
    char **temp = realloc(lines, lineCount * sizeof(char *));
    if (temp == NULL) {
      perror("Memory allocation failed");
      // Free previously allocated lines
      for (int i = 0; i < lineCount - 1; i++) {
        free(lines[i]);
      }
      free(lines);
      fclose(f);
      return EXIT_FAILURE;
    }
    lines = temp;
    lines[lineCount - 1] = strdup(buffer);
    if (lines[lineCount - 1] == NULL) {
      perror("Memory allocation failed");
      for (int i = 0; i < lineCount - 1; i++) {
        free(lines[i]);
      }
      free(lines);
      fclose(f);
      return EXIT_FAILURE;
    }
  }
  fclose(f);

  // Ensure there are at least three lines.
  if (lineCount < 3) {
    // If not, add empty lines as needed.
    int needed = 3 - lineCount;
    char *emptyLine = strdup("\n");
    if (emptyLine == NULL) {
      perror("Memory allocation failed");
      for (int i = 0; i < lineCount; i++) {
        free(lines[i]);
      }
      free(lines);
      return EXIT_FAILURE;
    }
    for (int i = 0; i < needed; i++) {
      char **temp = realloc(lines, (lineCount + 1) * sizeof(char *));
      if (temp == NULL) {
        perror("Memory allocation failed");
        for (int j = 0; j < lineCount; j++) {
          free(lines[j]);
        }
        free(lines);
        free(emptyLine);
        return EXIT_FAILURE;
      }
      lines = temp;
      lines[lineCount] = strdup(emptyLine);
      if (lines[lineCount] == NULL) {
        perror("Memory allocation failed");
        for (int j = 0; j < lineCount; j++) {
          free(lines[j]);
        }
        free(lines);
        free(emptyLine);
        return EXIT_FAILURE;
      }
      lineCount++;
    }
    free(emptyLine);
  }

  // Prepare the new third line with the entryCount value
  char newLine[MAX_LINE_LENGTH];
  snprintf(newLine, sizeof(newLine), "%d\n", entryCount);
  free(lines[2]); // free the old third line
  lines[2] = strdup(newLine);
  if (lines[2] == NULL) {
    perror("Memory allocation failed for new third line");
    for (int i = 0; i < lineCount; i++) {
      free(lines[i]);
    }
    free(lines);
    return EXIT_FAILURE;
  }

  // Open the file for writing (overwrite)
  f = fopen(dataFilePath, "w");
  if (f == NULL) {
    perror("Error opening file for writing");
    for (int i = 0; i < lineCount; i++) {
      free(lines[i]);
    }
    free(lines);
    return EXIT_FAILURE;
  }

  // Write all lines back to the file
  for (int i = 0; i < lineCount; i++) {
    if (fputs(lines[i], f) == EOF) {
      perror("Error writing to file");
      fclose(f);
      for (int j = 0; j < lineCount; j++) {
        free(lines[j]);
      }
      free(lines);
      return EXIT_FAILURE;
    }
    free(lines[i]);
  }
  free(lines);
  fclose(f);
  return EXIT_SUCCESS;
}
