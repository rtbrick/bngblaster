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
string(APPEND CMAKE_C_FLAGS " -pthread -Wno-error=sequence-point")

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

# Add AF_XDP support
#
# The AF_XDP socket API (xsk.h) was removed from libbpf with version 1.0
# and moved to libxdp (xdp/xsk.h). Prefer libxdp if available, otherwise
# fall back to the deprecated API of libbpf < 1.0.
if(BNGBLASTER_AF_XDP)
    message(STATUS "Build bngblaster with AF_XDP support")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBXDP "libxdp")
    pkg_check_modules(LIBBPF "libbpf")
    if(LIBXDP_FOUND AND LIBBPF_FOUND)
        message(STATUS "Found libxdp ${LIBXDP_VERSION} via pkg-config")
        add_definitions(-DBNGBLASTER_AF_XDP -DBNGBLASTER_LIBXDP)
        include_directories(${LIBXDP_INCLUDE_DIRS} ${LIBBPF_INCLUDE_DIRS})
        target_link_libraries(bngblaster ${LIBXDP_LIBRARIES} ${LIBBPF_LIBRARIES})
    elseif(LIBBPF_FOUND)
        if(LIBBPF_VERSION VERSION_GREATER_EQUAL "1.0")
            message(FATAL_ERROR "libbpf ${LIBBPF_VERSION} does not provide the AF_XDP socket API "
                                "(removed in libbpf 1.0), install libxdp (e.g. libxdp-dev) "
                                "required for BNGBLASTER_AF_XDP")
        endif()
        message(STATUS "Found libbpf ${LIBBPF_VERSION} via pkg-config")
        add_definitions(-DBNGBLASTER_AF_XDP)
        include_directories(${LIBBPF_INCLUDE_DIRS})
        target_link_libraries(bngblaster ${LIBBPF_LIBRARIES})
    else()
        message(FATAL_ERROR "libxdp or libbpf < 1.0 not found, required for BNGBLASTER_AF_XDP")
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

install(TARGETS bngblaster DESTINATION bin)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build bngblaster tests")
    enable_testing()
    add_subdirectory(test)
endif()