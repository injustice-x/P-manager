#include "../include/context1.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_INPUT 256

// Define the global context variable.
passwordManagerContext *globalContext = NULL;

/*
 * readFile:
 * Open (or create) the file 'filename' and return its entire contents as a
 * null-terminated string (dynamically allocated). Caller must free the result.
 */
char *readFile(const char *filename) {
  int fd =
      open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    perror("open");
    return NULL;
  }
  FILE *fp = fdopen(fd, "r+");
  if (!fp) {
    perror("fdopen");
    close(fd);
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(fp);
    return NULL;
  }
  long filesize = ftell(fp);
  if (filesize < 0) {
    perror("ftell");
    fclose(fp);
    return NULL;
  }
  rewind(fp);
  char *buffer = malloc(filesize + 1);
  if (!buffer) {
    perror("malloc");
    fclose(fp);
    return NULL;
  }
  size_t bytesRead = fread(buffer, 1, filesize, fp);
  if (ferror(fp)) {
    perror("fread");
    free(buffer);
    fclose(fp);
    return NULL;
  }
  buffer[bytesRead] = '\0';
  fclose(fp);
  return buffer;
}

/*
 * writeFile:
 * Open (or create) the file 'filename' for writing (truncating any previous
 * content) and write the provided 'content' string into it. Returns 0 on
 * success, -1 on error.
 */
int writeFile(const char *filename, const char *content) {
  int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd == -1) {
    perror("open");
    return -1;
  }
  FILE *fp = fdopen(fd, "w");
  if (!fp) {
    perror("fdopen");
    close(fd);
    return -1;
  }
  size_t contentLen = strlen(content);
  size_t bytesWritten = fwrite(content, 1, contentLen, fp);
  if (bytesWritten != contentLen) {
    perror("fwrite");
    fclose(fp);
    return -1;
  }
  fflush(fp);
  fclose(fp);
  return 0;
}

/*
 * passwordManagerInit:
 * Allocate and initialize a new passwordManagerContext with the given
 * usersFilePath.
 */
passwordManagerContext *passwordManagerInit(const char *usersFilePath) {
  passwordManagerContext *ctx = calloc(1, sizeof(passwordManagerContext));
  if (!ctx)
    return NULL;
  ctx->usersFilePath = strdup(usersFilePath);
  ctx->userCount = 0;
  ctx->currentUser = NULL;
  return ctx;
}

/*
 * passwordManagerFree:
 * Free the passwordManagerContext and all its associated memory.
 */
void passwordManagerFree(passwordManagerContext *ctx) {
  if (!ctx)
    return;
  if (ctx->usersFilePath)
    free(ctx->usersFilePath);
  if (ctx->currentUser) {
    currentUserFree(ctx->currentUser);
  }
  free(ctx);
}

/*
 * getUserContext:
 * For this simple example, simply return the current user stored in
 * globalContext.
 */
userTable *getUserContext(const char *usersFilePath) {
  (void)usersFilePath; // unused parameter in this demo
  if (globalContext) {
    return globalContext->currentUser;
  }
  return NULL;
}

/*
 * currentUserFree:
 * Free a userTable, its associated username/password hash strings, and
 * userData.
 */
void currentUserFree(userTable *currentUser) {
  if (!currentUser)
    return;
  if (currentUser->usernameHash)
    free(currentUser->usernameHash);
  if (currentUser->passwordHash)
    free(currentUser->passwordHash);
  if (currentUser->userData) {
    if (currentUser->userData->entries) {
      for (size_t i = 0; i < currentUser->userData->entryCount; i++) {
        if (currentUser->userData->entries[i].website)
          free(currentUser->userData->entries[i].website);
        if (currentUser->userData->entries[i].username)
          free(currentUser->userData->entries[i].username);
        if (currentUser->userData->entries[i].password)
          free(currentUser->userData->entries[i].password);
      }
      free(currentUser->userData->entries);
    }
    if (currentUser->userData->dataFilePath)
      free(currentUser->userData->dataFilePath);
    if (currentUser->userData->encryptionKey)
      free(currentUser->userData->encryptionKey);
    free(currentUser->userData);
  }
  free(currentUser);
}

/*
 * Helper: Convert a binary buffer into a hex string.
 * The returned string is dynamically allocated; caller must free it.
 */
static char *hexStringFromBytes(const unsigned char *bytes, unsigned int len) {
  char *hex = malloc(2 * len + 1);
  if (!hex)
    return NULL;
  for (unsigned int i = 0; i < len; i++) {
    sprintf(hex + i * 2, "%02x", bytes[i]);
  }
  hex[2 * len] = '\0';
  return hex;
}

/*
 * hashIt:
 * A simple implementation using the djb2 algorithm.
 * It computes a 64-bit hash of the input password,
 * returns a dynamically allocated buffer (of size sizeof(unsigned long))
 * and sets *digest_len accordingly.
 */
unsigned char *hashIt(const char *password, unsigned int *digest_len) {
  unsigned long hash = 5381;
  int c;
  while ((c = *password++))
    hash = ((hash << 5) + hash) + c; // hash * 33 + c
  *digest_len = sizeof(unsigned long);
  unsigned char *result = malloc(*digest_len);
  if (!result)
    return NULL;
  memcpy(result, &hash, *digest_len);
  return result;
}

/*
 * addUser:
 * Given a pointer to a userTable, and a username and password,
 * compute their hashes (using hashIt), convert them to hex strings,
 * store them in the userTable, and initialize userData if needed.
 * Returns 0 on success, -1 on error.
 */
int addUser(userTable *currentUser, const char *username,
            const char *password) {
  if (!currentUser || !username || !password)
    return -1;

  unsigned int unameDigestLen = 0, pwdDigestLen = 0;
  unsigned char *unameHashBytes = hashIt(username, &unameDigestLen);
  if (!unameHashBytes)
    return -1;
  unsigned char *pwdHashBytes = hashIt(password, &pwdDigestLen);
  if (!pwdHashBytes) {
    free(unameHashBytes);
    return -1;
  }
  char *unameHex = hexStringFromBytes(unameHashBytes, unameDigestLen);
  char *pwdHex = hexStringFromBytes(pwdHashBytes, pwdDigestLen);
  free(unameHashBytes);
  free(pwdHashBytes);
  if (!unameHex || !pwdHex) {
    free(unameHex);
    free(pwdHex);
    return -1;
  }
  if (currentUser->usernameHash)
    free(currentUser->usernameHash);
  if (currentUser->passwordHash)
    free(currentUser->passwordHash);
  currentUser->usernameHash = unameHex;
  currentUser->passwordHash = pwdHex;

  // Initialize userData if it hasn't been set.
  if (!currentUser->userData) {
    currentUser->userData = calloc(1, sizeof(userData));
    if (!currentUser->userData)
      return -1;
    currentUser->userData->entryCount = 0;
    currentUser->userData->entries = NULL;
    currentUser->userData->dataFilePath = NULL;
    currentUser->userData->encryptionKey = NULL;
    currentUser->userData->encryptioKeyLen = 0;
    currentUser->userData->isLoggedin = false;
  }

  return 0;
}

/*
 * addPassword:
 * Adds one or more password entries to the current user's userData.
 * In this demo, we assume newData.entryCount > 0 and newData.entries points
 * to an array of passwordEntry containing new entries.
 * Returns 0 on success, -1 on error.
 */
int addPassword(userTable *currentUser, userData newData) {
  if (!currentUser || !currentUser->userData || !newData.entries ||
      newData.entryCount == 0)
    return -1;

  size_t oldCount = currentUser->userData->entryCount;
  size_t newCount = newData.entryCount;
  passwordEntry *newEntries =
      realloc(currentUser->userData->entries,
              (oldCount + newCount) * sizeof(passwordEntry));
  if (!newEntries)
    return -1;
  currentUser->userData->entries = newEntries;
  for (size_t i = 0; i < newCount; i++) {
    currentUser->userData->entries[oldCount + i].website =
        strdup(newData.entries[i].website);
    currentUser->userData->entries[oldCount + i].username =
        strdup(newData.entries[i].username);
    currentUser->userData->entries[oldCount + i].password =
        strdup(newData.entries[i].password);
    if (!currentUser->userData->entries[oldCount + i].website ||
        !currentUser->userData->entries[oldCount + i].username ||
        !currentUser->userData->entries[oldCount + i].password) {
      return -1;
    }
  }
  currentUser->userData->entryCount = oldCount + newCount;
  return 0;
}

/*
 * authUser:
 * Prompts for username and password, computes their hashes, and compares them
 * with the stored hashes in globalContext->currentUser. If they match, marks
 * the user as logged in. Returns a pointer to the authenticated userTable on
 * success, or NULL on failure.
 */
userTable *authUser(passwordManagerContext *globalContext) {
  if (!globalContext || !globalContext->currentUser) {
    printf("No user registered.\n");
    return NULL;
  }
  char username[MAX_INPUT], password[MAX_INPUT];
  printf("=== Login ===\n");
  printf("Enter username: ");
  if (!fgets(username, sizeof(username), stdin))
    return NULL;
  username[strcspn(username, "\n")] = '\0';
  printf("Enter password: ");
  if (!fgets(password, sizeof(password), stdin))
    return NULL;
  password[strcspn(password, "\n")] = '\0';

  unsigned int unameDigestLen = 0, pwdDigestLen = 0;
  unsigned char *unameHashBytes = hashIt(username, &unameDigestLen);
  unsigned char *pwdHashBytes = hashIt(password, &pwdDigestLen);
  if (!unameHashBytes || !pwdHashBytes) {
    free(unameHashBytes);
    free(pwdHashBytes);
    return NULL;
  }
  char *computedUnameHash = hexStringFromBytes(unameHashBytes, unameDigestLen);
  char *computedPwdHash = hexStringFromBytes(pwdHashBytes, pwdDigestLen);
  free(unameHashBytes);
  free(pwdHashBytes);
  if (!computedUnameHash || !computedPwdHash) {
    free(computedUnameHash);
    free(computedPwdHash);
    return NULL;
  }

  userTable *storedUser = globalContext->currentUser;
  if (strcmp(storedUser->usernameHash, computedUnameHash) == 0 &&
      strcmp(storedUser->passwordHash, computedPwdHash) == 0) {
    storedUser->userData->isLoggedin = true;
    printf("Authentication successful.\n");
    free(computedUnameHash);
    free(computedPwdHash);
    return storedUser;
  } else {
    printf("Invalid credentials.\n");
    free(computedUnameHash);
    free(computedPwdHash);
    return NULL;
  }
}

#ifdef TEST_ALL_FUNCTIONS
// A demonstration main() that exercises signup, login, file I/O, and adding a
// password entry.
int main(void) {
  // Initialize global context.
  globalContext = passwordManagerInit("users.txt");
  if (!globalContext) {
    fprintf(stderr, "Failed to initialize password manager context.\n");
    return EXIT_FAILURE;
  }

  // Create a new user.
  userTable *newUser = calloc(1, sizeof(userTable));
  if (!newUser) {
    perror("calloc newUser");
    passwordManagerFree(globalContext);
    return EXIT_FAILURE;
  }

  char signupUsername[MAX_INPUT], signupPassword[MAX_INPUT];
  printf("=== Signup ===\n");
  printf("Enter username: ");
  if (!fgets(signupUsername, sizeof(signupUsername), stdin)) {
    fprintf(stderr, "Error reading username.\n");
    free(newUser);
    passwordManagerFree(globalContext);
    return EXIT_FAILURE;
  }
  signupUsername[strcspn(signupUsername, "\n")] = '\0';

  printf("Enter password: ");
  if (!fgets(signupPassword, sizeof(signupPassword), stdin)) {
    fprintf(stderr, "Error reading password.\n");
    free(newUser);
    passwordManagerFree(globalContext);
    return EXIT_FAILURE;
  }
  signupPassword[strcspn(signupPassword, "\n")] = '\0';

  if (addUser(newUser, signupUsername, signupPassword) != 0) {
    fprintf(stderr, "Failed to add user.\n");
    free(newUser);
    passwordManagerFree(globalContext);
    return EXIT_FAILURE;
  }

  globalContext->currentUser = newUser;
  printf("Signup successful.\n");

  // Attempt authentication.
  userTable *authenticated = authUser(globalContext);
  if (!authenticated) {
    printf("Authentication failed.\n");
  }

  // Demonstrate addPassword:
  // Create a dummy password entry to add.
  userData newData = {0};
  newData.entryCount = 1;
  newData.entries = calloc(1, sizeof(passwordEntry));
  if (!newData.entries) {
    fprintf(stderr, "Allocation error for password entry.\n");
  } else {
    newData.entries[0].website = strdup("example.com");
    newData.entries[0].username = strdup("user@example.com");
    newData.entries[0].password = strdup("secretpassword");
    if (addPassword(newUser, newData) == 0) {
      printf("Password entry added successfully.\n");
    } else {
      printf("Failed to add password entry.\n");
    }
    free(newData.entries[0].website);
    free(newData.entries[0].username);
    free(newData.entries[0].password);
    free(newData.entries);
  }

  // Write some user data to file.
  char buffer[512];
  snprintf(buffer, sizeof(buffer), "usernameHash: %s\npasswordHash: %s\n",
           newUser->usernameHash, newUser->passwordHash);
  if (writeFile("user_data.txt", buffer) == 0) {
    printf("User data written to file.\n");
  } else {
    printf("Failed to write user data to file.\n");
  }

  // Read the file back.
  char *fileContents = readFile("user_data.txt");
  if (fileContents) {
    printf("Read from file:\n%s\n", fileContents);
    free(fileContents);
  } else {
    printf("Failed to read from file.\n");
  }

  // Clean up.
  passwordManagerFree(globalContext);
  globalContext = NULL;
  return EXIT_SUCCESS;
}
#endif
