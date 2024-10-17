#include "../include/awsv4.h"

int awstime(char *output, const size_t len) {
    size_t tslen = 20;

    if(output == NULL) {
        error("output buffer must not be null\n");
        return -1;
    }

    if(len < tslen) {
        error("buffer size too small for timestamp. must be at least: %zu\n", tslen);
        return -1;
    }

    time_t now = time(NULL);
    if(now ==((time_t) -1)) {
        error("failed to get current time\n");
        return -1;
    }

    struct tm *utc = gmtime(&now);
    if(!utc) {
        error("failed to convert time to utc\n");
        return -1;
    }

    if(strftime(output, tslen, "%Y%m%dT%H%M%SZ", utc) == 0) {
        error("failed to format timestamp\n");
        return -1;
    }

    output[len - 1] = '\0';

    return 0;
}

int awsdate(char *output, const size_t len) {
    size_t datelen = 9;

    if(output == NULL) {
        error("output buffer must not be null\n");
        return -1;
    }

    if(len < datelen) {
        error("output buffer size too small for date. must be at least: %zu\n", datelen);
        return -1;
    }

    time_t now = time(NULL);
    if(now ==((time_t) -1)) {
        error("failed to get current time\n");
        return -1;
    }

    struct tm *utc = gmtime(&now);
    if(!utc) {
        error("failed to convert time to utc\n");
        return -1;
    }

    if(strftime(output, datelen, "%Y%m%d", utc) == 0) {
        error("failed to format date\n");
        return -1;
    }

    output[len - 1] = '\0';

    return 0;
}

int tohex(char *output, const size_t olen, const unsigned char *input, const size_t ilen) {
    if(olen < HEX_LEN) {
        error("output buffer size too small for hex. must be at least: %d\n", HEX_LEN);
        return -1;
    }

    for (int i = 0; i < ilen; i++) {
        sprintf(output + (i * 2), "%02x", input[i]);
    }
    
    output[ilen * 2] = '\0';

    return 0;
}

int sha256hex(char *output, const size_t len, const char *input) {
    if(len < HEX_LEN) {
        error("output buffer size too small for hex. must be at least: %d\n", HEX_LEN);
        return -1;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if(SHA256((unsigned char*) input, strlen(input), hash) == NULL) {
        error("failed to get sha256\n");
        return -1;
    }

    if(tohex(output, len, hash, sizeof(hash)) != 0) {
        error("failed to convert sha256 to hex\n");
        return -1;
    }

    return 0;
}

int getcanonicalreq(
    char *output, 
    const size_t len,
    const char *httpmethod,
    const char *bucket,
    const char *region,
    const char *payloadhex,
    const char *timestamp
) {
    char canonical[BUFSIZ];
    snprintf(
        canonical, 
        sizeof(canonical),
        "%s\n"
        "/\n"
        "encoding-type=url&list-type=2&prefix=\n"
        "host:%s.s3.%s.amazonaws.com\n"
        "x-amz-content-sha256:%s\n"
        "x-amz-date:%s\n"
        "\n"
        "host;x-amz-content-sha256;x-amz-date\n"
        "%s",
        httpmethod,
        bucket,
        region,
        payloadhex,
        timestamp,
        payloadhex
    );

    size_t canonicalsize = strlen(canonical);
    if(canonicalsize + 1 > len) {
        error("output buffer size too small for canonical. must be at least: %zu\n", canonicalsize);
        return -1;
    }

    strncpy(output, canonical, len - 1);

    output[len - 1] = '\0';

    return 0;
}

int getstringtosign(
    char *output, 
    const size_t len,
    const char *timestamp,
    const char *date,
    const char *region,
    const char *canonicalhex
) {
    char tosign[BUFSIZ];
    snprintf(
        tosign, 
        sizeof(tosign),
        "AWS4-HMAC-SHA256\n"
        "%s\n"
        "%s/%s/s3/aws4_request\n"
        "%s", 
        timestamp, 
        date,
        region,
        canonicalhex
    );

    size_t tosignsize = strlen(tosign);
    if(len < tosignsize + 1) {
        error("output buffer size too small for string to sign. must be at least: %zu\n", tosignsize);
        return -1;
    }

    strncpy(output, tosign, len - 1);

    output[len - 1] = '\0';

    return 0;
}

int createsignature(
    char *output, 
    const size_t len, 
    const char *tosign,
    const char *secret,
    const char *date,
    const char *region
) {
    if(len < HEX_LEN) {
        error("output buffer size too small for hex. must be at least: %d\n", HEX_LEN);
        return -1;
    }

    unsigned char kdate[32], kregion[32], kservice[32], signer[32];
    char awssecret[256];
    snprintf(
        awssecret,
        sizeof(awssecret),
        "AWS4%s",
        secret
    );

    char *service = "s3";
    char *aws4req = "aws4_request";

    if(HMAC(
        EVP_sha256(), 
        awssecret, 
        strlen(awssecret), 
        (unsigned char*) date, 
        strlen(date),
        kdate, 
        NULL
    ) == NULL) {
        error("failed to get hmac sha for secret + date\n");
        return -1;
    }

    if(HMAC(
        EVP_sha256(), 
        kdate, 
        SHA256_DIGEST_LENGTH, 
        (unsigned char*) region,
        strlen(region), 
        kregion, 
        NULL
    ) == NULL) {
        error("failed to get hmac sha for date + region\n");
        return -1;
    }

    if(HMAC(
        EVP_sha256(), 
        kregion, 
        SHA256_DIGEST_LENGTH, 
        (unsigned char *) service, 
        strlen(service), 
        kservice, 
        NULL
    ) == NULL) {
        error("failed to get hmac sha for region + service\n");
        return -1;
    }

    if(HMAC(
        EVP_sha256(), 
        kservice, 
        SHA256_DIGEST_LENGTH, 
        (unsigned char *) aws4req, 
        strlen(aws4req), 
        signer, 
        NULL
    ) == NULL) {
        error("failed to get hmac sha for service + request type\n");
        return -1;
    }

    // hash/hex the string to sign using the signer
    unsigned char signedhash[SHA256_DIGEST_LENGTH];
    if (HMAC(
        EVP_sha256(), 
        signer, 
        sizeof(signer), 
        (unsigned char *) tosign, 
        strlen(tosign), 
        signedhash, 
        NULL
    ) == NULL) {
        error("failed to get hmac sha for service + request type\n");
        return -1;
    }

    tohex(output, len, signedhash, sizeof(signedhash));

    return 0;
}