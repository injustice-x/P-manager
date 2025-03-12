#ifndef CONTEXT_H
#define CONTEXT_H

#include <cjson/cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
  unsigned char *usernameHash;
  unsigned char *passwordHash;
} hashes;

typedef struct {
  hashes *hash;
  userContext *currentContext;
} user;

typedef struct {
  const char *filePath;
  user *currentUser;
} passwordManagerContext;

extern passwordManagerContext *globalContext;
extern user *currentUser;

/*main functions*/
passwordManagerContext *initPasswordManagerContext(const char *dataFilePath);
int logIn(passwordManagerContext *globalContext);
user *getUser(passwordManagerContext *globalContext);
int addUser(passwordManagerContext *globalContext);
int addPassword(passwordManagerContext *globalContext);
int editPassword(passwordManagerContext *globalContext);
void freeGlobalContext(passwordManagerContext *globalContext);

/*helper functions*/
unsigned char *hashIt(char *input, unsigned int *digest_len);
hashes *getHashes(const char *dataFilePath);
int writeHashes(hashes *hash, const char *dataFilePath);
int *writeData(unsigned char *encrypted, const char *dataFilePath);
unsigned char *getData(const char *dataFilePath);
char *jsonEntries(entry *entries, char *name, size_t entryCount);
entry *unJsonEntries(char *jsonString, int *numEntries);
int *encryptData(const char *dataFilePath, entry *entries);
int *decryptData(const char *dataFilePath, entry *entries);

#endif // !CONTEXT_H
