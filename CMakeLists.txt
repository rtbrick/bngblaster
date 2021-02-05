# BNG Blaster
#
# For Debug Build Try below command 
#cmake -DCMAKE_BUILD_TYPE=Debug .
cmake_minimum_required (VERSION 3.0)
project(bngblaster LANGUAGES C VERSION 0.0.0)

option(BNGBLASTER_TESTS "Build unit tests (requires cmocka)" OFF)

configure_file ("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("Debug Build")
    set(CMAKE_BUILD_TYPE Debug)
    add_definitions(-DBBL_DEBUG)
else()
    message("Release Build")
    set(CMAKE_BUILD_TYPE Release)
endif()

FILE(GLOB BBL_SOURCES src/*.c)
add_executable(bngblaster ${BBL_SOURCES})

# libdict will be statically linked 
find_library(libdict NAMES libdict.a REQUIRED)

target_link_libraries(bngblaster curses crypto jansson ${libdict} m)
target_compile_options(bngblaster PRIVATE -Werror -Wall -Wextra -m64 -mtune=generic)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build Tests")
    enable_testing()
    add_subdirectory(test)
endif()

install(TARGETS bngblaster DESTINATION sbin)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
set(CPACK_DEBIAN_LIB_PACKAGE_DEPENDS "libssl1.1, libncurses5, libjansson4")
set(CPACK_DEBIAN_LIB_PACKAGE_NAME "bngblaster")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_PACKAGE_CONTACT "RtBrick <bngblaster@rtbrick.com>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/rtbrick/bngblaster")
if (NOT DEFINED BNGBLASTER_VERSION)
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
else()
    set(CPACK_PACKAGE_VERSION ${BNGBLASTER_VERSION})
endif()
include(CPack)