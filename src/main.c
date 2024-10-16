#include "../include/awsv4.h"

int main() {
    char *region = "us-west-2";


    // get time/date stamps
    char timestamp[20]; 
    if(awstime(timestamp, sizeof(timestamp)) != 0) {
        fprintf(stderr, "failed to get aws time\n");
        return -1;
    }    
    fprintf(stdout, "aws time: %s\n", timestamp);

    char date[20]; 
    if(awsdate(date, sizeof(date)) != 0) {
        fprintf(stderr, "failed to get aws date\n");
        return -1;
    }
    fprintf(stdout, "aws date: %s\n\n\n", date);


    // hash/hex the payload
    char *payload = "";
    char payloadhex[HEX_LEN];
    if(sha256hex(payloadhex, sizeof(payloadhex), payload) != 0) {
        fprintf(stderr, "failed to sha256 hex the payload\n");
        return -1;  
    }
    fprintf(stdout, "payload hex: %s\n\n\n", payloadhex);


    // build canonical request
    char canonical[BUFSIZ];
    if(getcanonicalreq(
        canonical, 
        sizeof(canonical), 
        "GET", 
        "dummybucket", 
        region, 
        payloadhex, 
        timestamp
    )) {
        fprintf(stderr, "failed to get canonical req\n");
        return -1;
    }
    fprintf(stdout, "canonical req:\n%s\n\n\n", canonical);


    // hash/hex the canonical request
    char canonicalhex[HEX_LEN];
    if(sha256hex(canonicalhex, sizeof(canonicalhex), canonical) != 0) {
        fprintf(stderr, "failed to sha256 hex the canonical request\n");
        return -1;  
    }
    fprintf(stdout, "canonical hex: %s\n\n\n", canonicalhex);


    // get string to sign
    char tosign[BUFSIZ];
    if(getstringtosign(
        tosign,
        sizeof(tosign),
        timestamp,
        date,
        region,
        canonicalhex
    ) != 0) {
        fprintf(stderr, "failed to get string to sign\n");
        return -1;  
    }
    fprintf(stdout, "string to sign:\n%s\n\n\n", tosign);


    // create signature
    char signature[HEX_LEN];
    if(createsignature(
        signature,
        sizeof(signature),
        tosign,
        "AWSDUMMYSECRETKEY",
        date,
        region
    ) != 0) {
        fprintf(stderr, "failed to create signature\n");
        return -1;  
    }
    fprintf(stdout, "signature: %s\n\n\n", signature);

    return 0;
}