#include "../include/context.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  entry *testJson;
  size_t count = 2;
  int numEntries = 2;
  testJson = malloc(sizeof(entry) * count);
  testJson[1].name = "name1";
  testJson[1].username = "username1";
  testJson[1].password = "password1";
  testJson[1].website = "website1";

  testJson[0].name = "name0";
  testJson[0].username = "username0";
  testJson[0].password = "password0";
  testJson[0].website = "website0";
  char *testJsonEntries = jsonEntries(testJson, "user", count);
  if (testJsonEntries != NULL) {
    /*printf("%s\n", testJsonEntries);*/
  } else {
    fprintf(stderr, "Failed to create JSON string\n");
  }
  entry *entries = unJsonEntries(testJsonEntries, &numEntries);
  if (!entries) {
    return EXIT_FAILURE;
  }

  // Print out each entry.
  for (int i = 0; i < numEntries; i++) {
    printf("Entry %d:\n", i);
    printf("  Name:     %s\n", entries[i].name);
    printf("  Website:  %s\n", entries[i].website);
    printf("  Username: %s\n", entries[i].username);
    printf("  Password: %s\n\n", entries[i].password);
  }

  // Free allocated memory.
  for (int i = 0; i < numEntries; i++) {
    free(entries[i].name);
    free(entries[i].website);
    free(entries[i].username);
    free(entries[i].password);
  }
  free(entries);
  free(testJson);
  free(testJsonEntries); // Free the allocated JSON string
  return EXIT_SUCCESS;
}
