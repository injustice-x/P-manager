#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>

userContext *signUp(user *users, size_t userCount) {
  userContext *newUser;
  newUser = malloc(sizeof(userContext));
  char *username, *password;
  printf("Enter username:");
  scanf("%s", username);

  return newUser;
};
