#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdbool.h>
typedef struct {
  unsigned char *passHash;
  int timeout = 3000;
} mPassword;

#endif // !CONTEXT_H
