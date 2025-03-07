#include "../include/context.h"

unsigned char *readFile(const char *filePath) {
  unsigned char *returnString;
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
