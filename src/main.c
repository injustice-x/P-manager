#include "../include/context.h"

int main(int argc, char *argv[]) {
  int choice;
  const char *usersFilePath;
  passwordManagerContext *globalContext =
      initPasswordManagerContext(usersFilePath);
  return EXIT_SUCCESS;
}
