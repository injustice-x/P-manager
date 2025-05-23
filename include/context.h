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
  unsigned char *ciphertext;
  int ciphertext_len;
  const unsigned char *key;
  unsigned char *iv;
  unsigned char *plaintext;
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
int loadEntries(passwordManagerContext *globalContext);
int writeEntries(passwordManagerContext *globalContext);
int getUser(passwordManagerContext *globalContext);
int addUser(passwordManagerContext *globalContext);
int addEntry(passwordManagerContext *globalContext);
entry *editEntry(entry *entries, int entryCount, int index);
int searchEntry(entry *entries, int entryCount);
int showVault(passwordManagerContext *globalContext);
int encryptData(unsigned char *plaintext, int *plaintext_len,
                const unsigned char *key, unsigned char **iv,
                unsigned char **ciphertext, int *ciphertext_len);
int decryptData(unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, unsigned char *iv,
                unsigned char **plaintext, int *plaintext_len);
void freeGlobalContext(passwordManagerContext *globalContext);

/*helper functions*/
int generateIV(unsigned char **iv);
void generateRandomPassword(char *password, int length);
unsigned char *hashIt(char *input, unsigned int *digest_len);
int writeData(const char *filePath, hashes *hash, int entryCount,
              unsigned char *iv, unsigned char *cipherText,
              int *ciphertext_len);
int getData(const char *path, hashes *hash, int *entryCount, unsigned char **iv,
            unsigned char **cipherText, int *ciphertext_len);
char *jsonEntries(entry *entries, const char *name, int entryCount);
entry *unJsonEntries(char *jsonString, int *numEntries);
unsigned char *deriveAesKey(unsigned char *master_hash, size_t hash_len,
                            char *user_salt);

#endif // !CONTEXT_H
