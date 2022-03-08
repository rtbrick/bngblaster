cmake_minimum_required (VERSION 3.10)
project(bngbalster-fuzzing C)

set(CMAKE_C_COMPILER "afl-gcc")
set(PROPERTIES
    POSITION_INDEPENDENT_CODE OFF)

include_directories("../src")
include_directories("../../common/src")

find_library(libdict NAMES libdict.a REQUIRED)
set(LINK_LIBS ${libdict} m)
add_executable(fuzz-protocols-decode protocols_decode.c ../src/bbl_protocols.c)
target_link_libraries(fuzz-protocols-decode ${LINK_LIBS})
target_compile_options(fuzz-protocols-decode PRIVATE -Wall -Wextra -pedantic)