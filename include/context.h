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
userContext *signUp(user *users, size_t userCount);
userContext *logIn(user *users, size_t userCount);
int addUser(passwordManagerContext *globalcontext);
int removeUser(passwordManagerContext *globalcontext);
int addPassword(userContext *currentuser);
int editPassword(userContext *currentuser);
void freeUserContext(userContext *currentUser);
void freeGlobalContext(passwordManagerContext *globalContext);

/*helper functions*/
unsigned char *hashIt(const char *input, unsigned int *digest_len);
unsigned char *readFile(const char *filePath);
int writeFile(const char *filePath, unsigned char *jsonString);
unsigned char *jsonIt(entry *entries);
unsigned char *jsonThis(user *users);
user *unJsonThis(unsigned char *usersJson);
int *encryptIt(const char *dataFilePath, entry *entries);

#endif // !CONTEXT_H
