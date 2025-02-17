#ifndef HASHPASS_H
#define HASHPASS_H

#include "context.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

unsigned char *hashPass(char *mPass);

#endif
