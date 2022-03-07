# BNG Blaster
#
# For Debug Build Try below command
#cmake -DCMAKE_BUILD_TYPE=Debug .
cmake_minimum_required (VERSION 3.10)
project(bngblaster LANGUAGES C VERSION 0.0.0)

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

set(CURSES_NEED_NCURSES TRUE)
include(FindCurses)
target_link_libraries(bngblaster ${CURSES_LIBRARIES} crypto jansson ${libdict} m)

set(PLATFORM_SPECIFIC_LIBS "-lpthread")
string(APPEND CMAKE_C_FLAGS "-pthread")

# add LwIP

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/lwip)
set(LWIP_DEFINITIONS LWIP_DEBUG=0)
set(LWIP_DEFINITIONS LWIP_TCPIP_CORE_LOCKING=1)
set(LWIP_DEFINITIONS LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS=1)

include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)
set(LWIP_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/lwip"
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib/"
    "${LWIP_DIR}/contrib/ports/unix/port/include"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/unix/Filelists.cmake)
target_include_directories(bngblaster PRIVATE ${LWIP_INCLUDE_DIRS})
target_compile_definitions(bngblaster PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_link_libraries(bngblaster ${LWIP_SANITIZER_LIBS} lwipcore lwipcontribportunix)

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
