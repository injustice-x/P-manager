#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIGEST_SIZE 32 // SHA3‑256
#define IV_SIZE 16     // AES-CBC IV

/**
 * writeData(): Overwrite the vault file with:
 *   1) username hash (32 bytes) + '\n'
 *   2) password hash (32 bytes) + '\n'
 *   3) entryCount    (ASCII decimal) + '\n'
 *   4) IV (32 hex chars) + '\n'   [if iv != NULL]
 *   5) ciphertext (binary)        [if ciphertext != NULL and len>0]
 */
int writeData(const char *filePath, hashes *hash, int entryCount,
              unsigned char *iv, unsigned char *cipherText,
              int *ciphertext_len) {
  FILE *f = fopen(filePath, "wb");
  if (!f) {
    perror("Error opening file for writing");
    return EXIT_FAILURE;
  }

  // 1) username hash
  if (fwrite(hash->usernameHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    perror("Error writing username hash");
    fclose(f);
    return EXIT_FAILURE;
  }
  fputc('\n', f);

  // 2) password hash
  if (fwrite(hash->passwordHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    perror("Error writing password hash");
    fclose(f);
    return EXIT_FAILURE;
  }
  fputc('\n', f);

  // 3) entry count
  if (fprintf(f, "%d\n", entryCount) < 0) {
    perror("Error writing entry count");
    fclose(f);
    return EXIT_FAILURE;
  }

  // 4) IV as hex string
  if (iv) {
    for (int i = 0; i < IV_SIZE; ++i) {
      // "%02x" prints each byte as two hex digits citeturn0search0
      if (fprintf(f, "%02x", iv[i]) < 0) {
        perror("Error writing IV");
        fclose(f);
        return EXIT_FAILURE;
      }
    }
  }
  fputc('\n', f);

  // 5) ciphertext blob
  if (cipherText && ciphertext_len && *ciphertext_len > 0) {
    if (fwrite(cipherText, 1, *ciphertext_len, f) != (size_t)*ciphertext_len) {
      perror("Error writing ciphertext");
      fclose(f);
      return EXIT_FAILURE;
    }
  }

  fclose(f);
  return EXIT_SUCCESS;
}

/**
 * getData(): Read the vault file produced by writeData().
 * - hash           : fills usernameHash + passwordHash
 * - entryCount     : reads decimal count
 * - iv             : allocates and fills IV (16 bytes) if present
 * - cipherText     : allocates and fills ciphertext blob
 * - ciphertext_len : sets length in bytes
 */
int getData(const char *path, hashes *hash, int *entryCount, unsigned char **iv,
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
  fgetc(f); // consume newline

  // 2) Read password hash
  if (fread(hash->passwordHash, 1, DIGEST_SIZE, f) != DIGEST_SIZE) {
    fprintf(stderr, "Error reading password hash\n");
    fclose(f);
    return EXIT_FAILURE;
  }
  fgetc(f);

  // 3) Read entry count
  if (fscanf(f, "%d\n", entryCount) != 1) {
    fprintf(stderr, "Error reading entry count\n");
    fclose(f);
    return EXIT_FAILURE;
  }

  // 4) Read IV line (hex)
  char iv_hex[IV_SIZE * 2 + 2] = {0};
  if (fgets(iv_hex, sizeof(iv_hex), f) != NULL &&
      strlen(iv_hex) >= (size_t)(IV_SIZE * 2)) {
    *iv = malloc(IV_SIZE);
    if (!*iv) {
      perror("malloc(iv) failed");
      fclose(f);
      return EXIT_FAILURE;
    }
    for (int i = 0; i < IV_SIZE; i++) {
      if (sscanf(&iv_hex[i * 2], "%2hhx", &(*iv)[i]) != 1) {
        fprintf(stderr, "Error parsing IV hex\n");
        free(*iv);
        fclose(f);
        return EXIT_FAILURE;
      }
    }
  } else {
    *iv = NULL;
  }

  // 5) Determine ciphertext size
  long data_start = ftell(f);
  if (data_start < 0) {
    perror("ftell failed");
    fclose(f);
    return EXIT_FAILURE;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    perror("fseek to end failed");
    fclose(f);
    return EXIT_FAILURE;
  }
  long total = ftell(f);
  if (total < 0) {
    perror("ftell end failed");
    fclose(f);
    return EXIT_FAILURE;
  }
  long size = total - data_start;

  // 6) Read ciphertext if any
  if (size > 0) {
    *cipherText = malloc(size);
    if (!*cipherText) {
      perror("malloc(cipherText) failed");
      fclose(f);
      return EXIT_FAILURE;
    }
    if (fseek(f, data_start, SEEK_SET) != 0) {
      perror("fseek back failed");
      free(*cipherText);
      fclose(f);
      return EXIT_FAILURE;
    }
    if (fread(*cipherText, 1, size, f) != (size_t)size) {
      fprintf(stderr, "Error reading ciphertext\n");
      free(*cipherText);
      fclose(f);
      return EXIT_FAILURE;
    }
    *ciphertext_len = (int)size;
  } else {
    *cipherText = NULL;
    *ciphertext_len = 0;
  }

  fclose(f);
  return EXIT_SUCCESS;
}
