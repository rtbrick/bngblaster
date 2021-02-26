cmake_minimum_required (VERSION 3.0)
project(bngbalster-fuzzing C)

set(CMAKE_C_COMPILER "afl-gcc")
set(PROPERTIES
    POSITION_INDEPENDENT_CODE OFF)

include_directories("../src")

add_executable(fuzz-protocols-decode protocols_decode.c ../src/bbl_protocols.c)
target_compile_options(fuzz-protocols-decode PRIVATE -Wall -Wextra -pedantic)

