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

  // Allocate memory for usernameHash and passwordHash
  hash->usernameHash = malloc(DIGEST_SIZE);
  hash->passwordHash = malloc(DIGEST_SIZE);
  if (!hash->usernameHash || !hash->passwordHash) {
    perror("Memory allocation failed for hashes");
    fclose(f);
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
  char iv_hex[IV_SIZE * 2 + 2] = {0}; // +2 for newline and null terminator
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

  // Determine the current position in the file
  long current_pos = ftell(f);
  if (current_pos == -1L) {
    perror("ftell failed");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Move to the end to determine file size
  if (fseek(f, 0, SEEK_END) != 0) {
    perror("fseek to end failed");
    fclose(f);
    return EXIT_FAILURE;
  }

  long total_size = ftell(f);
  if (total_size == -1L) {
    perror("ftell at end failed");
    fclose(f);
    return EXIT_FAILURE;
  }

  // Calculate the size of the ciphertext
  long dataSize = total_size - current_pos;
  if (dataSize > 0) {
    *cipherText = malloc(dataSize);
    if (*cipherText == NULL) {
      fprintf(stderr, "Memory allocation failed for ciphertext.\n");
      fclose(f);
      return EXIT_FAILURE;
    }
    if (fseek(f, current_pos, SEEK_SET) != 0) {
      perror("fseek back to data failed");
      free(*cipherText);
      fclose(f);
      return EXIT_FAILURE;
    }
    if (fread(*cipherText, 1, dataSize, f) != (size_t)dataSize) {
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
