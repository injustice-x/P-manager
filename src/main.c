#include "../include/context.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  int opt;
  const char *dataFilePath = NULL;
  while ((opt = getopt(argc, argv, "f:")) != -1) {
    switch (opt) {
    case 'f':
      dataFilePath = strdup(optarg);
      break;
    default: /* '?' */
      fprintf(stderr, "Usage: %s -f <value>\n", argv[0]);
      return 1;
    }
  }
  if (access(dataFilePath, F_OK) == 0) {
    printf("file exists\n");
    // file exists
  } else {
    printf("file doesnt exists\n");
  }
  passwordManagerContext *globalContext =
      initPasswordManagerContext(dataFilePath);

  freeGlobalContext(globalContext);
  free((char *)dataFilePath);

  return EXIT_SUCCESS;
}
