#!/bin/bash

mkdir -p target
gcc -Wall -DDEBUG awsv4.h awsv4.c main.c -lssl -lcrypto -o target/awsv4