#include "../include/context.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  entry *test;
  size_t count = 2;
  test = malloc(sizeof(entry) * count);
  test[1].username = "ahsifsda";
  test[1].password = "password";
  test[1].website = "website";

  test[0].username = "1111111";
  test[0].password = "222222";
  test[0].website = "3333333";

  char *testJsonEntries = jsonEntries(test, "name", count);
  if (testJsonEntries != NULL) {
    printf("%s\n", testJsonEntries);
    free(testJsonEntries); // Free the allocated JSON string
  } else {
    fprintf(stderr, "Failed to create JSON string\n");
  }
  free(test);
  return EXIT_SUCCESS;
}
