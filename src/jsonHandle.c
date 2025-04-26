#include "../include/context.h"
#include <cjson/cJSON.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

char *jsonEntries(entry *entries, const char *name, int entryCount) {
  char *out = NULL;
  cJSON *root = NULL;
  cJSON *arr = NULL;
  cJSON *item = NULL;

  // 1) Create root object
  root = cJSON_CreateObject();
  if (!root) {
    goto cleanup;
  }

  // 2) Add username
  if (!cJSON_AddStringToObject(root, "username", name)) {
    goto cleanup;
  }

  // 3) Add Entries array
  arr = cJSON_AddArrayToObject(root, "Entries");
  if (!arr) {
    goto cleanup;
  }

  // 4) Populate array if any entries
  for (int i = 0; i < entryCount; ++i) {
    item = cJSON_CreateObject();
    if (!item) {
      goto cleanup;
    }
    if (!cJSON_AddStringToObject(item, "website", entries[i].website) ||
        !cJSON_AddStringToObject(item, "name", entries[i].name) ||
        !cJSON_AddStringToObject(item, "username", entries[i].username) ||
        !cJSON_AddStringToObject(item, "password", entries[i].password)) {
      cJSON_Delete(item);
      goto cleanup;
    }
    cJSON_AddItemToArray(arr, item);
    item = NULL; // ownership transferred
  }

  // 5) Print JSON
  out = cJSON_PrintUnformatted(root);
  if (!out) {
    goto cleanup;
  }

cleanup:
  // 6) Clean up cJSON tree
  if (root) {
    cJSON_Delete(root);
  }
  // 7) Return printed JSON (may be NULL on error)
  return out;
}

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
