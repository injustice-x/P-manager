#ifndef CONTEXT_H
#define CONTEXT_H

#include <cjson/cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *name;
  char *website;
  char *username;
  char *password;
} entry;

typedef struct {
  size_t entryCount;
  entry *entries;
  unsigned char *encryptionKey;
  size_t *encryptionKeyLen;
} userContext;

typedef struct {
  char *usernameHash;
  char *passwordHash;
  userContext *currentContext;
} user;

typedef struct {
  char *filePath;
  user *currentUser;
} passwordManagerContext;

extern passwordManagerContext *globalContext;
extern user *currentUser;

/*main functions*/
passwordManagerContext *initPasswordManagerContext(const char *usersFilePath);
userContext *logIn(passwordManagerContext *globalContext);
int addUser(passwordManagerContext *globalContext);
int addPassword(passwordManagerContext *globalContext);
int editPassword(passwordManagerContext *globalContext);
void freeUserContext(passwordManagerContext *globalContext);
void freeGlobalContext(passwordManagerContext *globalContext);

/*helper functions*/
unsigned char *hashIt(const char *input, unsigned int *digest_len);
unsigned char *readFile(const char *filePath);
int writeFile(const char *filePath, char *jsonString);
char *jsonEntries(entry *entries, char *name, size_t entryCount);
entry *unJsonEntries(char *jsonString, int *numEntries);
int *encryptData(const char *dataFilePath, entry *entries);
int *decryptData(const char *dataFilePath, entry *entries);

#endif // !CONTEXT_H
