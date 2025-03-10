#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>

userContext *signUp(passwordManagerContext *globalContext) {
  userContext *newUser;
  newUser = malloc(sizeof(userContext));
  char *username, *password;
  printf("Enter username:");
  scanf("%s", username);
  printf("Enter password:");
  scanf("%s", password);
  globalContext->currentUser = newUser;
  addUser(globalContext);

  return newUser;
};
