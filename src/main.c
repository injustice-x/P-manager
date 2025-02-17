#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  char *name;
  printf("enter the name of the user:\n");
  scanf("%49s", name);
  printf("%s", name);
  return 0;
}
