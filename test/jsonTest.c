#include "../include/context.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  entry *test;
  test = malloc(sizeof(entry));
  test->username = "username";
  test->password = "password";
  test->website = "website";

  char *testJsonEntries = jsonEntries(test, "name", 1);
  if (testJsonEntries != NULL) {
    printf("%s\n", testJsonEntries);
    free(testJsonEntries); // Free the allocated JSON string
  } else {
    fprintf(stderr, "Failed to create JSON string\n");
  }
  return EXIT_SUCCESS;
}
