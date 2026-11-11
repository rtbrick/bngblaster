
FILE(GLOB LSPGEN_SOURCES src/*.c)
list(SORT LSPGEN_SOURCES)

# Deterministic randomness for symbol name creation, source properties
# are scoped to the directory of the target (also for the common sources).
foreach(_file ${LSPGEN_SOURCES} ${COMMON_SOURCES})
    file(SHA1 ${_file} checksum)
    string(SUBSTRING ${checksum} 0 8 checksum)
    set_property(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum}")
endforeach()

add_executable(lspgen ${COMMON_SOURCES} ${LSPGEN_SOURCES})
target_link_libraries(lspgen crypto jansson ${libdict} m)

bbl_reproducible_build(lspgen)

if(BNGBLASTER_CPU_NATIVE)
    target_compile_options(lspgen PRIVATE -Werror -Wall -Wextra -Wno-deprecated-declarations -pedantic -march=native -mtune=native)
else()
    target_compile_options(lspgen PRIVATE -Werror -Wall -Wextra -Wno-deprecated-declarations -pedantic -mtune=generic)
endif()

# Optional IPO. Do not use IPO if it's not supported by compiler.
check_ipo_supported(RESULT result OUTPUT output)
if(result)
  set_property(TARGET lspgen PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message(WARNING "IPO is not supported: ${output}")
endif()

install(TARGETS lspgen DESTINATION bin)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build lspgen tests")
    enable_testing()
    add_subdirectory(test)
endif()