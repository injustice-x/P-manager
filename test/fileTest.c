#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 256

int main(void) {
  FILE *fp = fopen("CMakeCache.txt", "r");
  if (fp == NULL) {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  char firstLine[MAX_LINE_LENGTH];
  char secondLine[MAX_LINE_LENGTH];

  // Read the first line
  if (fgets(firstLine, sizeof(firstLine), fp) == NULL) {
    fprintf(stderr, "Error or no first line in file\n");
    fclose(fp);
    return EXIT_FAILURE;
  }
  // Remove the newline character if present
  firstLine[strcspn(firstLine, "\n")] = '\0';

  // Read the second line
  if (fgets(secondLine, sizeof(secondLine), fp) == NULL) {
    fprintf(stderr, "Error or no second line in file\n");
    fclose(fp);
    return EXIT_FAILURE;
  }
  // Remove the newline character if present
  secondLine[strcspn(secondLine, "\n")] = '\0';

  // Print the results
  printf("First line: %s\n", firstLine);
  printf("Second line: %s\n", secondLine);

  fclose(fp);
  return EXIT_SUCCESS;
}
