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
  bool isLoggedin;
} userData;

typedef struct {
  char *usernameHash;
  char *passwordHash;
  userData *userData;
} userTable;

typedef struct {
  char *usersFilePath;
  userTable *users;
  size_t userCount;
  userTable *currentUser;
} passwordManagerContext;

extern passwordManagerContext *globalContext;

passwordManagerContext *passwordManagerInit(const char *usersFilePath);
int addPassword(userTable *currentUser, userData user);
int addUser(userTable *currentUser, const char *username, const char *password);
void passwordManagerFree(passwordManagerContext *globalContext);
void currentUserFree(userTable *currentUser);
#endif // !CONTEXT_H
