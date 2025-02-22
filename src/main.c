#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int choice;
  const char *usersFilePath;
  passwordManagerContext *globalContext =
      initPasswordManagerContext(usersFilePath);
  printf("1.sign up\n2.log in\n3.Exit");
  while (1) {
    printf("Enter your choice:");
    scanf("%d", &choice);

    switch (choice) {
    case 1:
      globalContext->currentUser = signUp(globalContext);
      break;
    case 2:
      globalContext->currentUser = logIn(globalContext);
      break;
    case 3:
      exit(0);
      break;
    default:
      printf("Enter your choice again");
      break;
    }
  }
  return EXIT_SUCCESS;
}
