#ifndef CONTEXT_H
#define CONTEXT_H

#include <cstddef>
#include <stddef.h>
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

passwordManagerContext *initPasswordManagerContext(const char *usersFilePath);

unsigned char *hashIt(const char *password, unsigned int *digest_len);

#endif // !CONTEXT_H
