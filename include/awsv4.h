#ifndef AWSV4_H
#define AWSV4_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#define info(fmt, ...) fprintf(stdout, "INFO: %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define error(fmt, ...) fprintf(stderr, "ERROR: %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#ifdef DEBUG
    #define debug(fmt, ...) fprintf(stderr, "DEBUG: %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define debug(fmt, ...)
#endif

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