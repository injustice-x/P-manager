#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *website;
  char *username;
  char *password;
} passwordEntry;

typedef struct {
  char *dataFilePath;
  size_t entryCount;
  passwordEntry *entries;
  unsigned char *encryptionKey;
  size_t encryptioKeyLen;
} userData;

typedef struct {
  char *usernameHash;
  char *passwordHash;
  userData *userData;
  bool isLoggedin;
} userTable;

typedef struct {
  char *usersFilePath;
  userTable *user;
  size_t userCount;
} passwordManagerContext;

extern passwordManagerContext *globalContext;

int passwordManagerInit(const char *dataFilePath, const char *userFilePath);
int addPassword(const char *dataFilePath);
int addUser(const char *userFilePath);
void passwordManagerFree(void);

#endif // !CONTEXT_H
