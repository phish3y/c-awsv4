#ifndef AWSV4_H
#define AWSV4_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#define HEX_LEN  SHA256_DIGEST_LENGTH * 2 + 1


int awstime(char *, const size_t);
int awsdate(char *, const size_t);
int sha256hex(char *, const size_t, const char *);
int getcanonicalreq(
    char *,
    const size_t,
    const char *,
    const char *,
    const char *,
    const char *,
    const char *
);
int getstringtosign(
    char *,
    const size_t,
    const char *,
    const char *,
    const char *,
    const char *
);
int createsignature(
    char *, 
    const size_t,
    const char *,
    const char *,
    const char *,
    const char *
);

#endif