
FILE(GLOB LSPGEN_SOURCES src/*.c)
list(SORT LSPGEN_SOURCES)

# Deterministic randomness for symbol name creation
foreach(_file ${LSPGEN_SOURCES})
    file(SHA1 ${_file} checksum)
    string(SUBSTRING ${checksum} 0 8 checksum)
    set_property(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum}")
endforeach()

add_executable(lspgen ${COMMON_SOURCES} ${LSPGEN_SOURCES})
target_link_libraries(lspgen crypto jansson ${libdict} m)

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 8.0)
    target_compile_options(lspgen PUBLIC "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=.")
endif()

target_compile_options(lspgen PRIVATE -Werror -Wall -Wextra -Wno-deprecated-declarations -pedantic -m64 -mtune=generic)
set_property(TARGET lspgen PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

install(TARGETS lspgen DESTINATION sbin)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build lspgen tests")
    enable_testing()
    add_subdirectory(test)
endif()