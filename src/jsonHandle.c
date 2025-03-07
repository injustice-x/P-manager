#include "../include/context.h"
#include <cjson/cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

entry *unJsonEntries(char *jsonEntries) {
  entry *jEntry;
  cJSON *jString = cJSON_Parse(jsonEntries);

  if (jString == NULL) {
    const char *errPtr = cJSON_GetErrorPtr();

    if (errPtr == NULL) {
      printf("error 5;\n");
      return NULL;
    }
    cJSON_Delete(jString);
  }
  return jEntry;
}

char *jsonEntries(entry *entries, char *name, size_t entryCount) {

  char *jsonString;
  cJSON *entriesTemp = NULL;
  cJSON *jsonEntry = cJSON_CreateObject();

  if (cJSON_AddStringToObject(jsonEntry, "username", name) == NULL) {
    printf("1\n");
    return NULL;
  }
  entriesTemp = cJSON_AddArrayToObject(jsonEntry, "Entries");
  if (entriesTemp == NULL) {
    printf("2\n");
    return NULL;
  }

  for (size_t i = 0; i < entryCount; ++i) {
    cJSON *entry = cJSON_CreateObject();
    if (cJSON_AddStringToObject(entry, "website", entries[i].website) == NULL) {
      return NULL;
    }
    if (cJSON_AddStringToObject(entry, "username", entries[i].username) ==
        NULL) {
      return NULL;
    }
    if (cJSON_AddStringToObject(entry, "password", entries[i].password) ==
        NULL) {
      return NULL;
    }
    printf("3\n");
    cJSON_AddItemToArray(entriesTemp, entry);
  }
  jsonString = cJSON_Print(jsonEntry);

  cJSON_Delete(jsonEntry);
  return jsonString;
}
