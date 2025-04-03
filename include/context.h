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
  unsigned char *encryptionKey;
  const unsigned char *ciphertext;
  int *ciphertext_len;
  const unsigned char *key;
  const unsigned char *iv;
  const unsigned char *plaintext;
  int *len, *plaintext_len;
} cryptoContext;

typedef struct {
  int entryCount;
  entry *entries;
  cryptoContext *crypto;
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
  const char *username;
  const char *filePath;
  user *currentUser;
} passwordManagerContext;

extern passwordManagerContext *globalContext;
extern user *currentUser;

/*main functions*/
passwordManagerContext *initPasswordManagerContext(const char *dataFilePath);
int logIn(passwordManagerContext *globalContext);
int getUser(passwordManagerContext *globalContext);
int addUser(passwordManagerContext *globalContext);
int addEntry(passwordManagerContext *globalContext);
int editEntry(passwordManagerContext *globalContext);
int showVault(passwordManagerContext *globalContext);
int encryptData(passwordManagerContext *globalContext);
int decryptData(passwordManagerContext *globalContext);
void freeGlobalContext(passwordManagerContext *globalContext);

/*helper functions*/
unsigned char *hashIt(char *input, unsigned int *digest_len);
hashes *getHashes(const char *dataFilePath);
int getEntryCount(const char *dataFilePath);
int writeEntryCount(const char *dataFilePath, int entryCount);
int writeHashes(hashes *hash, const char *dataFilePath, int entryCount);
int writeData(unsigned char *encrypted, const char *dataFilePath,
              int entryCount);
unsigned char *getData(const char *dataFilePath);
char *jsonEntries(entry *entries, const char *name, int entryCount);
entry *unJsonEntries(char *jsonString, int *numEntries);
unsigned char *deriveAesKey(unsigned char *master_hash, size_t hash_len,
                            char *user_salt);

#endif // !CONTEXT_H
