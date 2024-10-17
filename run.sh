#!/bin/bash

mkdir -p target
gcc -Wall -DDEBUG include/awsv4.h src/awsv4.c src/main.c -lssl -lcrypto -o target/awsv4
./target/awsv4
