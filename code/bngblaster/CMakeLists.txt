FILE(GLOB BBL_SOURCES src/*.c src/io/*.c src/isis/*.c src/ospf/*.c src/ldp/*.c src/bgp/*.c)
list(SORT BBL_SOURCES)

# Deterministic randomness for symbol name creation
foreach(_file ${BBL_SOURCES})
    file(SHA1 ${_file} checksum)
    string(SUBSTRING ${checksum} 0 8 checksum)
    set_property(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum}")
endforeach()

add_executable(bngblaster ${COMMON_SOURCES} ${BBL_SOURCES})

set(PLATFORM_SPECIFIC_LIBS "-lpthread")
string(APPEND CMAKE_C_FLAGS "-pthread")

# Add curses support

set(CURSES_NEED_NCURSES TRUE)
include(FindCurses)
target_link_libraries(bngblaster ${CURSES_LIBRARIES} crypto jansson ${libdict} m)

# Add LwIP support
add_definitions(-DBNGBLASTER_LWIP)

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

# Add DPDK support
if(BNGBLASTER_DPDK)
    message(STATUS "Build bngblaster with DPDK support")
    find_package(PkgConfig REQUIRED)
    if (PKG_CONFIG_FOUND)
        pkg_check_modules(DPDK "libdpdk")
        if (DPDK_FOUND)
            message(STATUS "Found DPDK via pkg-config")
            add_definitions(-DBNGBLASTER_DPDK)
            add_definitions(${DPDK_CFLAGS} -march=native -mtune=native)
            set(DPDK_LIBS -Wl,--whole-archive ${DPDK_LIBRARIES} -lpthread -lnuma -ldl -Wl,--no-whole-archive)
            include_directories(${DPDK_INCLUDE_DIR})    
            target_link_libraries(bngblaster ${DPDK_LIBS})
        endif()
    endif()    
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 8.0)
    target_compile_options(bngblaster PUBLIC "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")
endif()

if(BNGBLASTER_CPU_NATIVE)
    target_compile_options(bngblaster PRIVATE -Werror -Wall -Wextra -Wno-deprecated-declarations -pedantic -march=native -mtune=native)
ELSE()
    target_compile_options(bngblaster PRIVATE -Werror -Wall -Wextra -Wno-deprecated-declarations -pedantic -mtune=generic)
ENDIF()

# Optional IPO. Do not use IPO if it's not supported by compiler.
check_ipo_supported(RESULT result OUTPUT output)
if(result)
  set_property(TARGET bngblaster PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message(WARNING "IPO is not supported: ${output}")
endif()

install(TARGETS bngblaster DESTINATION sbin)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build bngblaster tests")
    enable_testing()
    add_subdirectory(test)
endif()