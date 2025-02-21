#include "../include/context.h"

#define MAX_INPUT 256

int main(int argc, char *argv[]) {

  const char *password = "mySecretPassword";
  unsigned int len = 0;
  unsigned char *digest = hashIt(password, &len);

  if (digest) {
    printf("SHA3-256 digest for password \"%s\":\n", password);
    for (unsigned int i = 0; i < len; i++)
      printf("%02x", digest[i]);
    printf("\n");
    free(digest);
  }

  return 0;
}
