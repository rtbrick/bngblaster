configure_file ("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
                "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h")

FILE(GLOB COMMON_SOURCES src/*.c)

# Deterministic randomness for symbol name creation
list(SORT COMMON_SOURCES)
foreach(_file ${COMMON_SOURCES})
    file(SHA1 ${_file} checksum)
    string(SUBSTRING ${checksum} 0 8 checksum)
    set_property(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum}")
endforeach()

# Export variable one level up
set(COMMON_SOURCES ${COMMON_SOURCES} PARENT_SCOPE)

# Build tests only if required
if(BNGBLASTER_TESTS)
    message("Build common tests")
    enable_testing()
    add_subdirectory(test)
endif()