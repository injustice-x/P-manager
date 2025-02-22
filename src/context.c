#include "../include/context.h"
#include <stddef.h>

passwordManagerContext *initPasswordManagerContext(const char *usersFilePath) {
  passwordManagerContext *globalConetxt;

  if (usersFilePath == NULL) {
    return NULL;
  }
  unsigned char *usersJason;
  usersJason = readFile(usersFilePath);
  if (usersJason == NULL) {

    globalConetxt->users = malloc(sizeof(user));
    globalConetxt->userCount = 1;
    globalConetxt->usersFilePath = strdup(usersFilePath);
    globalConetxt->currentUser = malloc(sizeof(userContext));
  } else {
    user *users;
    users = unJsonThis(usersJason);
    size_t userCount;

    globalConetxt->users = users;
    globalConetxt->userCount = userCount;
    globalConetxt->usersFilePath = strdup(usersFilePath);

    globalConetxt->currentUser = malloc(sizeof(userContext));
  }
  if (globalConetxt->users == NULL) {
    printf("error allocating memory:1");
    return NULL;
  }

  if (globalConetxt->currentUser == NULL) {
    printf("error allocating memory:1");
    return NULL;
  };
  return globalConetxt;
}

