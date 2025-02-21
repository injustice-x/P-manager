#include "../include/context.h"

#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50

void signUp(passwordManagerContext *globalContext);
void logIn(passwordManagerContext *globalContext);

userTable *authUser(passwordManagerContext *globalContext) {
  userTable *currentUser;

  return currentUser;
}

void signUp(passwordManagerContext *globalContext) {
  char username[MAX_USERNAME_LEN];
  char password[MAX_PASSWORD_LEN];

  printf("Enter new username: ");
  scanf("%s", username);

  // Check if the username already exists
  for (int i = 0; i < user_count; i++) {
    if (strcmp(users[i].username, username) == 0) {
      printf("Username already exists. Please choose another.\n");
      return;
    }
  }
  printf("Enter new password: ");
  scanf("%s", password);

  // Save the new user record
  strcpy(users[user_count].username, username);
  strcpy(users[user_count].password, password);
  user_count++;

  printf("User registered successfully!\n");
}
