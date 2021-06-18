# BNG Blaster
#
# For Debug Build Try below command
#cmake -DCMAKE_BUILD_TYPE=Debug .
cmake_minimum_required (VERSION 3.10)
project(bngblaster LANGUAGES C VERSION 0.0.0)

option(BNGBLASTER_TESTS "Build unit tests (requires cmocka)" OFF)
option(BNGBLASTER_NETMAP "Build with netmap support" OFF)

configure_file ("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h")

set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("Debug Build")
    set(CMAKE_BUILD_TYPE Debug)
    add_definitions(-DBBL_DEBUG)
else()
    message("Release Build")
    set(CMAKE_BUILD_TYPE Release)
endif()

FILE(GLOB BBL_SOURCES src/*.c)
list(SORT BBL_SOURCES)
# Deterministic randomness for symbol name creation
foreach(_file ${BBL_SOURCES})
    file(SHA1 ${_file} checksum)
    string(SUBSTRING ${checksum} 0 8 checksum)
    set_property(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum}")
endforeach()
add_executable(bngblaster ${BBL_SOURCES})

# libdict will be statically linked
find_library(libdict NAMES libdict.a REQUIRED)

set(CURSES_NEED_NCURSES TRUE)
include(FindCurses)
target_link_libraries(bngblaster ${CURSES_LIBRARIES} crypto jansson ${libdict} m)

SET(PLATFORM_SPECIFIC_LIBS "-lpthread")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")


# add experimental netmap support
if(BNGBLASTER_NETMAP)
    add_definitions(-DBNGBLASTER_NETMAP)
    target_link_libraries(bngblaster netmap)
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 8.0)
    target_compile_options(bngblaster PUBLIC "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")
endif()
target_compile_options(bngblaster PRIVATE -Werror -Wall -Wextra -m64 -mtune=generic)
set_property(TARGET bngblaster PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build Tests")
    enable_testing()
    add_subdirectory(test)
endif()

install(TARGETS bngblaster DESTINATION sbin)

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1, libncurses5, libjansson4")
set(CPACK_DEBIAN_LIB_PACKAGE_NAME "bngblaster")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "RtBrick BNG Blaster")
set(CPACK_PACKAGE_CONTACT "RtBrick <bngblaster@rtbrick.com>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/rtbrick/bngblaster")
if (NOT DEFINED BNGBLASTER_VERSION)
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
else()
    set(CPACK_PACKAGE_VERSION ${BNGBLASTER_VERSION})
endif()
include(CPack)
