#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#define MAX_NAME_LEN 100
#define MAX_USERNAME_LEN 100
#define MAX_PASSWORD_LEN 100
#define MAX_WEBSITE_LEN 100

int showVault(passwordManagerContext *globalContext) {
  int noEntries = getEntryCount(globalContext->filePath);

  if (0 == noEntries) {
    printf("Vault is Empty!!!");
    return 0;
  }

  if (globalContext->currentUser->currentContext->entries == NULL) {
    entry *entries = malloc(sizeof(entry) * noEntries);
    globalContext->currentUser->currentContext->entries = entries;
    decryptData(globalContext);
    entries = unJsonEntries(
        (char *)globalContext->currentUser->currentContext->crypto->plaintext,
        &globalContext->currentUser->currentContext->entryCount);
    return 0;
  }

  return 0;
}

int addEntry(passwordManagerContext *globalContext) {
  int *size = &globalContext->currentUser->currentContext->entryCount;
  entry *entries = globalContext->currentUser->currentContext->entries;

  if (*size == 0) {
    entries = malloc(sizeof(entry));
    if (entries == NULL) {
      perror("memory allocation failed");
      return EXIT_FAILURE;
    }
  } else {
    entries = realloc(entries, (*size + 1) * sizeof(entry));
    if (entries == NULL) {
      perror("memory reallocation failed");
      return EXIT_FAILURE;
    }
  }
  globalContext->currentUser->currentContext->entries = entries;

  // Use the new entry index (which is the old count) for the new entry.
  int index = *size;

  // Allocate memory for each string field.
  entries[index].name = malloc(MAX_NAME_LEN);
  entries[index].username = malloc(MAX_USERNAME_LEN);
  entries[index].password = malloc(MAX_PASSWORD_LEN);
  entries[index].website = malloc(MAX_WEBSITE_LEN);

  if (!entries[index].name || !entries[index].username ||
      !entries[index].password || !entries[index].website) {
    perror("memory allocation failed for entry strings");
    return EXIT_FAILURE;
  }

  printf("Enter name of the entry: ");
  fgets(entries[index].name, MAX_NAME_LEN, stdin);
  entries[index].name[strcspn(entries[index].name, "\n")] = '\0';

  printf("Enter username: ");
  fgets(entries[index].username, MAX_USERNAME_LEN, stdin);
  entries[index].username[strcspn(entries[index].username, "\n")] = '\0';

  printf("Enter password: ");
  fgets(entries[index].password, MAX_PASSWORD_LEN, stdin);
  entries[index].password[strcspn(entries[index].password, "\n")] = '\0';

  printf("Enter website: ");
  fgets(entries[index].website, MAX_WEBSITE_LEN, stdin);
  entries[index].website[strcspn(entries[index].website, "\n")] = '\0';

  (*size)++;
  return 0;
}
