cmake_minimum_required(VERSION 3.15)
project(crypto_framework C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(crypto)

message(Library\ source\ file\ configured:)
FOREACH (F ${SRC_FILES})
    MESSAGE(${F})
ENDFOREACH (F)

add_library(crypto_framework SHARED ${SRC_FILES})
target_include_directories(crypto_framework PRIVATE include)