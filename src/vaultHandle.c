#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>

int showVault(passwordManagerContext *globalContext) {
  int noEntries = getEntryCount(globalContext->filePath);
  if (0 == noEntries) {
    printf("Vault is Empty!!!");
    return 0;
  }

  entry *entries = malloc(sizeof(entry) * noEntries);

  globalContext->currentUser->currentContext->entries = entries;
  return 0;
}
