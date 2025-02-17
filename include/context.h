#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *webside;
  char *username;
  char *password;
} passwordEntry;

typedef struct {
  char *dataFilePath;
  passwordEntry *entries;
  size_t entryCount;
  unsigned char *encryptionKey;
  size_t encryptioKeyLen;
  bool isLoggedin;
} passwordManagerContext;

extern passwordManagerContext *globalContext;

int passwordManagerInit(const char *dataFilePath);
void passwordManagerFree(void);

#endif // !CONTEXT_H
