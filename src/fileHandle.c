#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>

#define DIGEST_SIZE 32 // SHA3‑256
#define IV_SIZE 16     // AES‑CBC IV

int writeData(const char *filePath, hashes *hash, int entryCount,
              unsigned char *iv, unsigned char *cipherText,
              int ciphertext_len) {
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

  // 4) Write IV as hex string
  for (int i = 0; i < IV_SIZE; i++) {
    if (fprintf(f, "%02x", iv[i]) < 0) {
      perror("Error writing IV");
      fclose(f);
      return EXIT_FAILURE;
    }
  }
  fputc('\n', f);

  // 5) Write ciphertext
  if (fwrite(cipherText, 1, ciphertext_len, f) != ciphertext_len) {
    perror("Error writing ciphertext");
    fclose(f);
    return EXIT_FAILURE;
  }

  fclose(f);
  return EXIT_SUCCESS;
}

int getData(const char *path, hashes *hash, int *entryCount, unsigned char *iv,
            unsigned char **cipherText, int *ciphertext_len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror("Error opening file");
    return EXIT_FAILURE;
  }

  // 1) Read username hash
  if (fread(hash->usernameHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    fprintf(stderr, "Error reading username hash\n");
    fclose(f);
    return EXIT_FAILURE;
  }
  if (fgetc(f) != '\n') {
    fprintf(stderr, "Expected newline after username hash\n");
    fclose(f);
    return EXIT_FAILURE;
  }

  // 2) Read password hash
  if (fread(hash->passwordHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    fprintf(stderr, "Error reading password hash\n");
    fclose(f);
    return EXIT_FAILURE;
  }
  if (fgetc(f) != '\n') {
    fprintf(stderr, "Expected newline after password hash\n");
    fclose(f);
    return EXIT_FAILURE;
  }

  // 3) Read entry count
  if (fscanf(f, "%d\n", entryCount) != 1) {
    fprintf(stderr, "Error reading entry count\n");
    fclose(f);
    return EXIT_FAILURE;
  }

  // 4) Read IV (32 hex characters representing 16 bytes)
  char iv_hex[33]; // 32 chars + null terminator
  if (fgets(iv_hex, sizeof(iv_hex), f) == NULL) {
    fprintf(stderr, "Error reading IV\n");
    fclose(f);
    return EXIT_FAILURE;
  }
  if (strlen(iv_hex) < 32) {
    fprintf(stderr, "Incomplete IV data\n");
    fclose(f);
    return EXIT_FAILURE;
  }
  for (int i = 0; i < IV_SIZE; i++) {
    if (sscanf(&iv_hex[i * 2], "%2hhx", &iv[i]) != 1) {
      fprintf(stderr, "Error parsing IV hex data\n");
      fclose(f);
      return EXIT_FAILURE;
    }
  }

  // 5) Read ciphertext
  // Determine current file position
  long offset = ftell(f);
  if (offset == -1L) {
    perror("ftell failed");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Seek to end to determine file size
  if (fseek(f, 0, SEEK_END) != 0) {
    perror("fseek to end failed");
    fclose(f);
    return EXIT_FAILURE;
  }
  long filesize = ftell(f);
  if (filesize == -1L) {
    perror("ftell at end failed");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Calculate ciphertext size
  long dataSize = filesize - offset;
  if (dataSize <= 0) {
    fprintf(stderr, "No ciphertext data found\n");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Allocate memory for ciphertext
  *cipherText = malloc(dataSize);
  if (!*cipherText) {
    perror("Memory allocation for ciphertext failed");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Read ciphertext
  if (fseek(f, offset, SEEK_SET) != 0) {
    perror("fseek to ciphertext position failed");
    free(*cipherText);
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

  fclose(f);
  return EXIT_SUCCESS;
}
