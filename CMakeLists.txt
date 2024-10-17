cmake_minimum_required(VERSION 3.0)
project(awsv4)

add_library(awsv4 SHARED src/awsv4.c)
target_include_directories(awsv4 PUBLIC include)

install(TARGETS awsv4 DESTINATION /usr/local/lib)
install(DIRECTORY include/ DESTINATION /usr/local/include)