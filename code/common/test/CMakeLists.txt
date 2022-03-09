set(LINK_LIBS cmocka m)

add_executable(test-utils utils.c ../src/utils.c)
target_link_libraries(test-utils ${LINK_LIBS})
target_compile_options(test-utils PRIVATE -Werror -Wall -Wextra)
add_test(NAME "TestUtils" COMMAND test-utils)