#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>

#define DIGEST_SIZE 32 // SHA3‑256
#define IV_SIZE 16     // AES‑CBC IV

int writeData(const char *filePath, hashes *hash, int entryCount,
              unsigned char *iv, unsigned char *cipherText,
              int *ciphertext_len) {
  FILE *f = fopen(filePath, "wb");
  if (!f) {
    perror("Error opening file for writing");
    return EXIT_FAILURE;
  }

  // 1) Write username hash
  if (fwrite(hash->usernameHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    perror("Error writing username hash");
    fclose(f);
    return EXIT_FAILURE;
  }
  fputc('\n', f);

  // 2) Write password hash
  if (fwrite(hash->passwordHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    perror("Error writing password hash");
    fclose(f);
    return EXIT_FAILURE;
  }
  fputc('\n', f);

  // 3) Write entry count
  if (fprintf(f, "%d\n", entryCount) < 0) {
    perror("Error writing entry count");
    fclose(f);
    return EXIT_FAILURE;
  }

  // 4) Write IV as hex string if iv is not NULL
  if (iv != NULL) {
    for (int i = 0; i < IV_SIZE; i++) {
      if (fprintf(f, "%02x", iv[i]) < 0) {
        perror("Error writing IV");
        fclose(f);
        return EXIT_FAILURE;
      }
    }
  }
  fputc('\n', f);

  // 5) Write ciphertext if cipherText is not NULL and length > 0
  if (cipherText != NULL && ciphertext_len > 0) {
    if (fwrite(cipherText, 1, *ciphertext_len, f) != *ciphertext_len) {
      perror("Error writing ciphertext");
      fclose(f);
      return EXIT_FAILURE;
    }
  }

  fclose(f);
  return EXIT_SUCCESS;
}

int getData(const char *path, hashes *hash, int *entryCount, unsigned char **iv,
            unsigned char **cipherText, int *ciphertext_len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  // Read username hash
  if (fread(hash->usernameHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    fprintf(stderr, "Error reading username hash\n");
    fclose(f);
    return EXIT_FAILURE;
  }
  fgetc(f); // Consume newline

  // Read password hash
  if (fread(hash->passwordHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    fprintf(stderr, "Error reading password hash\n");
    fclose(f);
    return EXIT_FAILURE;
  }
  fgetc(f); // Consume newline

  // Read entry count
  if (fscanf(f, "%d\n", entryCount) != 1) {
    fprintf(stderr, "Error reading entry count\n");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Attempt to read IV
  char iv_hex[IV_SIZE * 2 + 1];
  if (fgets(iv_hex, sizeof(iv_hex), f) != NULL &&
      strlen(iv_hex) >= IV_SIZE * 2) {
    *iv = malloc(IV_SIZE);
    if (*iv == NULL) {
      fprintf(stderr, "Memory allocation failed for IV.\n");
      fclose(f);
      return EXIT_FAILURE;
    }
    for (int i = 0; i < IV_SIZE; i++) {
      sscanf(&iv_hex[i * 2], "%2hhx", &(*iv)[i]);
    }
  } else {
    *iv = NULL;
  }

  // Read ciphertext
  fseek(f, 0, SEEK_END);
  long filesize = ftell(f);
  fseek(f, 0, SEEK_SET);

  // Skip over the already read data
  fseek(f,
        DIGEST_SIZE * 2 + 2 + snprintf(NULL, 0, "%d\n", *entryCount) + 1 +
            (iv ? IV_SIZE * 2 + 1 : 0),
        SEEK_SET);

  long dataSize = filesize - ftell(f);
  if (dataSize > 0) {
    *cipherText = malloc(dataSize);
    if (*cipherText == NULL) {
      fprintf(stderr, "Memory allocation failed for ciphertext.\n");
      fclose(f);
      return EXIT_FAILURE;
    }
    if (fread(*cipherText, 1, dataSize, f) != dataSize) {
      fprintf(stderr, "Error reading ciphertext data\n");
      free(*cipherText);
      fclose(f);
      return EXIT_FAILURE;
    }
    *ciphertext_len = (int)dataSize;
  } else {
    *cipherText = NULL;
    *ciphertext_len = 0;
  }

  fclose(f);
  return EXIT_SUCCESS;
}
