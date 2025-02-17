#include "../include/hashPass.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
    char name[50]; // Allocate memory for 'name'
    char mPassword[50]; // Ensure sufficient space for the password

    printf("Enter the name of the user:\n");
    if (fgets(name, sizeof(name), stdin) != NULL) {
        // Remove the trailing newline character, if present
        size_t len = strlen(name);
        if (len > 0 && name[len - 1] == '\n') {
            name[len - 1] = '\0';
        }
    } else {
        fprintf(stderr, "Error reading user name.\n");
        return 1;
    }

    printf("Enter master password:\n");
    if (fgets(mPassword, sizeof(mPassword), stdin) != NULL) {
        // Remove the trailing newline character, if present
        size_t len = strlen(mPassword);
        if (len > 0 && mPassword[len - 1] == '\n') {
            mPassword[len - 1] = '\0';
        }
    } else {
        fprintf(stderr, "Error reading master password.\n");
        return 1;
    }

    unsigned char *hashed = hashPass(mPassword);

    return 0;
}
