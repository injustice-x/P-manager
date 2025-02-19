#include "../include/context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int addUser(passwordManagerContext *globalContext, const char *username,
            const char *password) {

    if (globalContext == NULL) {
        fprintf(stderr, "Error: Global context is not initialized.\n");
        return -1;
    }
    if (username == NULL || password == NULL) {
        fprintf(stderr, "Error: Username or password is NULL.\n");
        return -1;
    }

    // Calculate the new count.
    size_t newCount = globalContext->userCount + 1;

    // Reallocate memory for the users array.
    userTable *temp = realloc(globalContext->users, newCount * sizeof(userTable));
    if (temp == NULL) {
        fprintf(stderr, "Error: failed to reallocate memory.\n");
        return -1;
    }
    globalContext->users = temp;

    // Get pointer to the new user slot.
    userTable *newUser = &globalContext->users[newCount - 1];

    // Save the username and password (hashes).
    newUser->usernameHash = strdup(username);
    newUser->passwordHash = strdup(password);
    if (newUser->usernameHash == NULL || newUser->passwordHash == NULL) {
        fprintf(stderr, "Error: failed to save user credentials.\n");
        free(newUser->usernameHash);
        free(newUser->passwordHash);
        return -1;
    }

    // Allocate memory for userData.
    newUser->userData = malloc(sizeof(userData));
    if (newUser->userData == NULL) {
        fprintf(stderr, "Error: failed to allocate memory for userData.\n");
        free(newUser->usernameHash);
        free(newUser->passwordHash);
        return -1;
    }
    // Initialize userData.
    memset(newUser->userData, 0, sizeof(userData));
    newUser->userData->entryCount = 0;
    newUser->userData->isLoggedin = false;

    // Update the user count.
    globalContext->userCount = newCount;
    return 0;
}
