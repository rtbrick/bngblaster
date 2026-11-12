# BNG Blaster
#
# For Debug Build Try below command
#cmake -DCMAKE_BUILD_TYPE=Debug .
cmake_minimum_required (VERSION 3.10)
project(bngblaster LANGUAGES C VERSION 0.0.0)
include(CheckIPOSupported)

if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    message(FATAL_ERROR "Host ${CMAKE_SYSTEM_NAME} is not supported!")
endif()

message("Compiler: ${CMAKE_C_COMPILER_ID} Version: ${CMAKE_C_COMPILER_VERSION}")

option(BNGBLASTER_TESTS "Build unit tests (requires cmocka)" OFF)
option(BNGBLASTER_INTEGRATION_TESTS "Add integration tests (requires root, pytest, GoBGP, FRR and BIRD)" OFF)
option(BNGBLASTER_DPDK "Build with dpdk support" OFF)
option(BNGBLASTER_AF_XDP "Build with AF_XDP support" OFF)
option(BNGBLASTER_TIMER_LOGGING "Build with timer logging support" OFF)
option(BNGBLASTER_CPU_NATIVE "Build for native CPU type" OFF)

set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

add_definitions(-D_GNU_SOURCE)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message("Debug Build")
    set(CMAKE_BUILD_TYPE Debug)
    add_definitions(-DBBL_DEBUG)
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    message("Release Build")
    set(CMAKE_BUILD_TYPE Release)
else()
    message("Release Build with Debug Symbols")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

if (BNGBLASTER_TIMER_LOGGING)
    add_definitions(-DBNGBLASTER_TIMER_LOGGING)
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "..." FORCE)
endif()

# libdict will be statically linked
find_library(libdict NAMES libdict.a REQUIRED)

# With -pedantic, clang also reports the GNU extensions and style used
# throughout the code (', ## __VA_ARGS__', 'f()' declarations, missing
# newline at the end of a file), which GCC does not report.
if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wno-gnu-zero-variadic-macro-arguments -Wno-strict-prototypes -Wno-newline-eof)
endif()

# Reproducible builds: map the source and build directory in debug information
# and macros, also on the link line for the LTO units compiled at link time.
if ((CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0) OR
    (CMAKE_C_COMPILER_ID MATCHES "Clang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10.0))
    set(BBL_FILE_PREFIX_MAP "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=." "-ffile-prefix-map=${CMAKE_BINARY_DIR}=.")
endif()

# CMake uses ThinLTO for Clang, which renames promoted local symbols with
# a suffix (.llvm.<hash>) derived from the module including its absolute
# source path, not mapped by -ffile-prefix-map. Full LTO does not promote.
if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_C_COMPILE_OPTIONS_IPO "-flto=full")
endif()

function(bbl_reproducible_build)
    foreach(_target ${ARGN})
        target_compile_options(${_target} PRIVATE ${BBL_FILE_PREFIX_MAP})
        foreach(_map ${BBL_FILE_PREFIX_MAP})
            set_property(TARGET ${_target} APPEND_STRING PROPERTY LINK_FLAGS " ${_map}")
        endforeach()
    endforeach()
endfunction()

# All targets of the calling directory, also the unit tests, with a
# deterministic random seed per target for those without one per source.
function(bbl_reproducible_build_directory)
    get_property(_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_target ${_targets})
        bbl_reproducible_build(${_target})
        target_compile_options(${_target} PRIVATE "-frandom-seed=${_target}")
    endforeach()
endfunction()

if(BNGBLASTER_TESTS OR BNGBLASTER_INTEGRATION_TESTS)
    include(CTest)
endif()
add_subdirectory(code)

if(BNGBLASTER_INTEGRATION_TESTS)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME IntegrationTests
             COMMAND ${Python3_EXECUTABLE} -m pytest -v ${CMAKE_SOURCE_DIR}/test/integration)
    set_tests_properties(IntegrationTests PROPERTIES
                         LABELS integration
                         ENVIRONMENT "BNGBLASTER_BIN=$<TARGET_FILE:bngblaster>")
endif()

install(FILES schemas/bngblaster-config.json DESTINATION share/bngblaster)
install(FILES packaging/bash-completion/bngblaster-cli DESTINATION share/bash-completion/completions)

# cpack
set(CPACK_GENERATOR "DEB")

if (BNGBLASTER_OS STREQUAL "ubuntu-18.04")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1, libncurses5, libjansson4")
elseif (BNGBLASTER_OS STREQUAL "ubuntu-20.04")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1, libncurses5, libjansson4")
else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3, libncurses6, libjansson4")
endif()
# bngblaster-cli, bgpupdate and ldpupdate
string(APPEND CPACK_DEBIAN_PACKAGE_DEPENDS ", python3")

set(CPACK_DEBIAN_LIB_PACKAGE_NAME "bngblaster")
set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "RtBrick BNG Blaster")
set(CPACK_PACKAGE_CONTACT "RtBrick <bngblaster@rtbrick.com>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/rtbrick/bngblaster")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postinst;${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postrm")
if (NOT DEFINED BNGBLASTER_VERSION)
    set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
else()
    set(CPACK_PACKAGE_VERSION ${BNGBLASTER_VERSION})
endif()
include(CPack)
