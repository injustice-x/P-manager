#include "../include/context.h"
#include <cjson/cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

entry *unJsonEntries(char *jsonString, int *numEntries) {
  entry *jEntry;
  cJSON *jString = cJSON_Parse(jsonString);
  if (jString == NULL) {
    fprintf(stderr, "JSON parsing error: %s\n", cJSON_GetErrorPtr());
    return NULL;
  }
  cJSON *username = cJSON_GetObjectItemCaseSensitive(jString, "username");
  if (cJSON_IsString(username) && (username->valuestring != NULL)) {
    printf("username: %s\n", username->valuestring);
  } else {
    fprintf(stderr, "Error: username field is missing or invalid.\n");
  }
  // Get the "Entries" object from the parsed JSON.
  cJSON *jData = cJSON_GetObjectItemCaseSensitive(jString, "Entries");
  if (!cJSON_IsArray(jData)) {
    fprintf(stderr, "\"Entries\" is not an array.\n");
    cJSON_Delete(jString);
    return NULL;
  }

  int arraySize = cJSON_GetArraySize(jData);
  if (numEntries) {
    *numEntries = arraySize;
  }

  jEntry = malloc(arraySize * sizeof(entry));
  if (!jEntry) {
    fprintf(stderr, "Memory allocation error.\n");
    cJSON_Delete(jString);
    return NULL;
  }

  for (int i = 0; i < arraySize; i++) {
    cJSON *item = cJSON_GetArrayItem(jData, i);
    cJSON *jWebsite = cJSON_GetObjectItemCaseSensitive(item, "website");
    cJSON *jName = cJSON_GetObjectItemCaseSensitive(item, "name");
    cJSON *jUsername = cJSON_GetObjectItemCaseSensitive(item, "username");
    cJSON *jPassword = cJSON_GetObjectItemCaseSensitive(item, "password");

    // Duplicate the strings to our structure (free these later when done).
    jEntry[i].website = (cJSON_IsString(jWebsite) && jWebsite->valuestring)
                            ? strdup(jWebsite->valuestring)
                            : NULL;
    jEntry[i].name = (cJSON_IsString(jName) && jName->valuestring)
                         ? strdup(jName->valuestring)
                         : NULL;
    jEntry[i].username = (cJSON_IsString(jUsername) && jUsername->valuestring)
                             ? strdup(jUsername->valuestring)
                             : NULL;
    jEntry[i].password = (cJSON_IsString(jPassword) && jPassword->valuestring)
                             ? strdup(jPassword->valuestring)
                             : NULL;
  }

  // Free the JSON structure as we have copied the needed values.
  cJSON_Delete(jString);
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

  if (entryCount == 0) {
    jsonString = cJSON_Print(jsonEntry);

    return jsonString;
  }
  for (size_t i = 0; i < entryCount; ++i) {
    cJSON *entry = cJSON_CreateObject();
    if (cJSON_AddStringToObject(entry, "website", entries[i].website) == NULL) {
      return NULL;
    }
    if (cJSON_AddStringToObject(entry, "name", entries[i].name) == NULL) {
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
