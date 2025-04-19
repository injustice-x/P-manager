#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIGEST_SIZE 32 // SHA3‑256
#define IV_SIZE 16     // AES‑CBC IV
int writeData(const char *filePath, hashes *hash, int entryCount,
              unsigned char *iv, unsigned char *cipherText,
              int *ciphertext_len) {
  FILE *f = fopen(filePath, "wb");

  if (!f)
    return EXIT_FAILURE;

  // 1)username hash
  fwrite(hash->usernameHash, 1, DIGEST_SIZE, f);
  fputc('\n', f);

  // 2)password hash
  fwrite(hash->passwordHash, 1, DIGEST_SIZE, f);
  fputc('\n', f);

  // 3)entrycouht
  fprintf(f, "%d\n", entryCount);

  // 4)iv
  for (int i = 0; i < IV_SIZE; i++) {
    fprintf(f, "%20x", iv[i]);
  }
  fputc('\n', f);

  // 5) cipher text
  fwrite(cipherText, 1, *ciphertext_len, f);
  fputc('\n', f);

  fclose(f);

  return EXIT_SUCCESS;
}
