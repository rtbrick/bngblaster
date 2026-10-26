# The test includes lspgen.c (with main renamed) to access
# its static functions, all other sources are linked.
set(LSPGEN_TEST_SOURCES ${LSPGEN_SOURCES})
list(FILTER LSPGEN_TEST_SOURCES EXCLUDE REGEX ".*/src/lspgen\\.c$")

add_executable(test-lspgen lspgen_test.c ${COMMON_SOURCES} ${LSPGEN_TEST_SOURCES})
target_include_directories(test-lspgen PRIVATE ../src ../../common/src)
target_link_libraries(test-lspgen cmocka crypto jansson ${libdict} m)
target_compile_options(test-lspgen PRIVATE -Werror -Wall -Wextra -Wno-deprecated-declarations)
add_test(NAME "TestLspgen" COMMAND test-lspgen)
