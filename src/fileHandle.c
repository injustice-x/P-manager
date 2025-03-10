#include "../include/context.h"

char *readFile(const char *filePath) {
  char *returnString;
  FILE *f = fopen(filePath, "r");
  if (f == NULL) {
    perror("error in opening file");
    return EXIT_FAILURE;
  }

  return returnString;
}

int writeFile(const char *filePath, char *jsonString) {
  FILE *f = fopen(filePath, "w");
  return 0;
}
