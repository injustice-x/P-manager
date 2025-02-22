#include "../include/context.h"
#include <cjson/cJSON.h>
#include <stddef.h>
#include <strings.h>

char *jsonEntries(entry *entries, char *name, size_t entryCount) {

  char *jsonString;
  cJSON *entriesTemp = NULL;
  cJSON *jsonEntry = cJSON_CreateObject();

  if (cJSON_AddStringToObject(jsonEntry, "username", name)) {
    return NULL;
  }
  entriesTemp = cJSON_AddArrayToObject(jsonEntry, "Entries");
  if (entriesTemp == NULL) {
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
    cJSON_AddItemToArray(entriesTemp, entry);
  }
  jsonString = cJSON_Print(jsonEntry);

  cJSON_Delete(jsonEntry);
  return jsonString;
}
