set(LINK_LIBS cmocka m)

add_executable(test-utils utils.c ../src/utils.c)
target_link_libraries(test-utils ${LINK_LIBS})
target_compile_options(test-utils PRIVATE -Werror -Wall -Wextra)
add_test(NAME "TestUtils" COMMAND test-utils)

add_executable(test-checksum checksum.c ../src/checksum.c)
target_link_libraries(test-checksum ${LINK_LIBS})
target_compile_options(test-checksum PRIVATE -Werror -Wall -Wextra)
add_test(NAME "TestChecksum" COMMAND test-checksum)

add_executable(test-timer timer.c ../src/timer.c ../src/logging.c)
target_link_libraries(test-timer ${LINK_LIBS})
target_compile_options(test-timer PRIVATE -Werror -Wall -Wextra -DBNGBLASTER_TIMER_LOGGING)
add_test(NAME "TestTimer" COMMAND test-timer)