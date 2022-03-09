FILE(GLOB BBL_SOURCES src/*.c src/isis/*.c)
list(SORT BBL_SOURCES)

# Deterministic randomness for symbol name creation
foreach(_file ${BBL_SOURCES})
    file(SHA1 ${_file} checksum)
    string(SUBSTRING ${checksum} 0 8 checksum)
    set_property(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum}")
endforeach()

add_executable(bngblaster ${COMMON_SOURCES} ${BBL_SOURCES})

set(CURSES_NEED_NCURSES TRUE)
include(FindCurses)
target_link_libraries(bngblaster ${CURSES_LIBRARIES} crypto jansson ${libdict} m)

set(PLATFORM_SPECIFIC_LIBS "-lpthread")
string(APPEND CMAKE_C_FLAGS "-pthread")

# add experimental netmap support
if(BNGBLASTER_NETMAP)
    add_definitions(-DBNGBLASTER_NETMAP)
    target_link_libraries(bngblaster netmap)
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 8.0)
    target_compile_options(bngblaster PUBLIC "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")
endif()
target_compile_options(bngblaster PRIVATE -Werror -Wall -Wextra -pedantic -m64 -mtune=generic)
set_property(TARGET bngblaster PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

install(TARGETS bngblaster DESTINATION sbin)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build bngblaster tests")
    enable_testing()
    add_subdirectory(test)
endif()

