include_directories ("../src/")

set(LINK_LIBS cmocka pcap m)

add_executable (test-protocols protocols.c ../src/bbl_protocols.c)
target_link_libraries (test-protocols ${LINK_LIBS})
target_compile_options(test-protocols PRIVATE -Werror -Wall -Wextra)
add_test (NAME "TestProtocols" COMMAND test-protocols)

add_executable (test-utils utils.c ../src/bbl_utils.c)
target_link_libraries (test-utils ${LINK_LIBS})
target_compile_options(test-utils PRIVATE -Werror -Wall -Wextra)
add_test (NAME "TestUtils" COMMAND test-utils)

add_executable (test-decode-pcap protocols_decode_pcap.c ../src/bbl_protocols.c)
target_link_libraries (test-decode-pcap ${LINK_LIBS})
target_compile_options(test-decode-pcap PRIVATE -Werror -Wall -Wextra)