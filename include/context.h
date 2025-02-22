#ifndef CONTEXT_H
#define CONTEXT_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *website;
  char *username;
  char *password;
} entry;

typedef struct {
  char *usernameHash;
  char *passwordHash;
  char *dataFilePathHash;
} user;

typedef struct {
  user *thisUser;
  char *dataFilePath;
  size_t *entryCount;
  entry *entries;
  unsigned char *encryptionKey;
  size_t *encryptionKeyLen;
} userContext;

typedef struct {
  char *usersFilePath;
  user *users;
  userContext *currentUser;
  size_t userCount;
} passwordManagerContext;

extern passwordManagerContext *globalContext;
extern userContext *currentUser;

/*main functions*/
passwordManagerContext *initPasswordManagerContext(const char *usersFilePath);
userContext *signUp(passwordManagerContext *globalContext);
userContext *logIn(passwordManagerContext *globalContext);
int addUser(passwordManagerContext *globalContext);
int removeUser(passwordManagerContext *globalContext);
int addPassword(passwordManagerContext *globalContext);
int editPassword(passwordManagerContext *globalContext);
void freeUserContext(passwordManagerContext *globalContext);
void freeGlobalContext(passwordManagerContext *globalContext);

/*helper functions*/
unsigned char *hashIt(const char *input, unsigned int *digest_len);
unsigned char *readFile(const char *filePath);
int writeFile(const char *filePath, unsigned char *jsonString);
unsigned char *jsonEntries(entry *entries);
entry *unJsonEntries(unsigned char *jsonEntries);
unsigned char *jsonUsers(user *users);
user *unJsonUsers(unsigned char *usersJson);
int *encryptData(const char *dataFilePath, entry *entries);
int *decryptData(const char *dataFilePath, entry *entries);

#endif // !CONTEXT_H
