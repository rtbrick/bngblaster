# BNG Blaster
#
# For Debug Build Try below command
#cmake -DCMAKE_BUILD_TYPE=Debug .
cmake_minimum_required (VERSION 3.10)
project(bngblaster LANGUAGES C VERSION 0.0.0)

if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    message(FATAL_ERROR "Host ${CMAKE_SYSTEM_NAME} is not supported!")
endif()

message("Compiler: ${CMAKE_C_COMPILER_ID} Version: ${CMAKE_C_COMPILER_VERSION}")

option(BNGBLASTER_TESTS "Build unit tests (requires cmocka)" OFF)
option(BNGBLASTER_NETMAP "Build with netmap support" OFF)

set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("Debug Build")
    set(CMAKE_BUILD_TYPE Debug)
    add_definitions(-DBBL_DEBUG)
else()
    message("Release Build")
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "..." FORCE)
endif()

# libdict will be statically linked
find_library(libdict NAMES libdict.a REQUIRED)

if(BNGBLASTER_TESTS)
    include(CTest)
endif()
add_subdirectory(code)

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
