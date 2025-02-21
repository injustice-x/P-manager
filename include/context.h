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
  size_t userCount;
  userTable *currentUser;
} passwordManagerContext;

extern passwordManagerContext *globalContext;

passwordManagerContext *passwordManagerInit(const char *usersFilePath);
void passwordManagerFree(passwordManagerContext *globalContext);
userTable *getUserContext(const char *usersFilePath);
void currentUserFree(userTable *currentUser);

userTable *authUser(passwordManagerContext *globalContext);
unsigned char *hashIt(const char *password, unsigned int *digest_len);
int addUser(userTable *currentUser, const char *username, const char *password);

int addPassword(userTable *currentUser, userData user);

#endif // !CONTEXT_H
