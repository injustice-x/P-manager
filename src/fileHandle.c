#include "../include/context.h"
#include <stdio.h>

/*char *readFile(const char *filePath) {*/

/*  char *returnString;*/
/*  FILE *f = fopen(filePath, "r");*/
/*  if (f == NULL) {*/
/*    perror("error in opening file");*/
/*    return EXIT_FAILURE;*/
/*  }*/
/**/
/*  return returnString;*/
/*}*/
int writeHashes(hashes *hash, const char *dataFilePath) {
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
  printf("done");

  fclose(f);
  return 0;
}

hashes *getHashes(const char *dataFilePath);
