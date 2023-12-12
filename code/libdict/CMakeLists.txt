# list of source files.
FILE(GLOB LIBDICT_SOURCES src/*.c)

# Deterministic randomness for symbol name creation
list(SORT LIBDICT_SOURCES)
foreach(_file ${LIBDICT_SOURCES})
    file(SHA1 ${_file} checksum)
    string(SUBSTRING ${checksum} 0 8 checksum)
    set_property(SOURCE ${_file} APPEND_STRING PROPERTY COMPILE_FLAGS "-frandom-seed=0x${checksum}")
endforeach()

# Export variable one level up
set(LIBDICT_SOURCES ${LIBDICT_SOURCES} PARENT_SCOPE)