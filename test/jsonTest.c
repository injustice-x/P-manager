#include "../include/context.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  entry *test;
  size_t count = 2;
  test = malloc(sizeof(entry) * count);
  test[1].username = "username1";
  test[1].name = "name1";
  test[1].password = "password1";
  test[1].website = "website1";

  test[0].username = "username0";
  test[0].name = "name0";
  test[0].password = "password0";
  test[0].website = "website0";

  char *testJsonEntries = jsonEntries(test, "user", count);
  if (testJsonEntries != NULL) {
    printf("%s\n", testJsonEntries);
    free(testJsonEntries); // Free the allocated JSON string
  } else {
    fprintf(stderr, "Failed to create JSON string\n");
  }
  free(test);
  return EXIT_SUCCESS;
}
