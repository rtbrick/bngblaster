include_directories("../src/")

# Disable LWIP for unit tests 
remove_definitions(-DBNGBLASTER_LWIP)

set(LINK_LIBS ${libdict} cmocka pcap m)

add_executable(test-protocols protocols.c ../src/bbl_protocols.c)
target_link_libraries(test-protocols ${LINK_LIBS})
target_compile_options(test-protocols PRIVATE -Werror -Wall -Wextra)
add_test(NAME "TestProtocols" COMMAND test-protocols)

add_executable(test-io-capture io_capture.c ../src/io/io_capture.c ../../common/src/logging.c)
target_include_directories(test-io-capture PRIVATE $<TARGET_PROPERTY:bngblaster,INCLUDE_DIRECTORIES>)
target_compile_definitions(test-io-capture PRIVATE $<TARGET_PROPERTY:bngblaster,COMPILE_DEFINITIONS>)
target_link_libraries(test-io-capture cmocka pthread ${CURSES_LIBRARIES})
target_compile_options(test-io-capture PRIVATE -Werror -Wall -Wextra)
target_link_options(test-io-capture PRIVATE -Wl,--wrap=realloc)
add_test(NAME "TestIoCapture" COMMAND test-io-capture)
set_tests_properties(TestIoCapture PROPERTIES TIMEOUT 30)

add_executable(test-decode-pcap protocols_decode_pcap.c ../src/bbl_protocols.c)
target_link_libraries(test-decode-pcap ${LINK_LIBS})
target_compile_options(test-decode-pcap PRIVATE -Werror -Wall -Wextra)

# The test includes isis_lsp.c, unused functions referencing the
# rest of BNG Blaster are removed by the linker.
add_executable(test-isis-lsp isis_lsp.c)
target_include_directories(test-isis-lsp PRIVATE $<TARGET_PROPERTY:bngblaster,INCLUDE_DIRECTORIES>)
target_compile_definitions(test-isis-lsp PRIVATE $<TARGET_PROPERTY:bngblaster,COMPILE_DEFINITIONS>)
target_link_libraries(test-isis-lsp ${libdict} cmocka)
target_compile_options(test-isis-lsp PRIVATE -Werror -Wall -Wextra -ffunction-sections -fdata-sections)
target_link_options(test-isis-lsp PRIVATE -Wl,--gc-sections)
add_test(NAME "TestIsisLsp" COMMAND test-isis-lsp)

if(BNGBLASTER_AF_XDP)
    # The test includes io_af_xdp.c, unused functions referencing the
    # rest of BNG Blaster are removed by the linker.
    add_executable(test-af-xdp af_xdp.c)
    target_include_directories(test-af-xdp PRIVATE $<TARGET_PROPERTY:bngblaster,INCLUDE_DIRECTORIES>)
    target_compile_definitions(test-af-xdp PRIVATE $<TARGET_PROPERTY:bngblaster,COMPILE_DEFINITIONS>)
    target_link_libraries(test-af-xdp cmocka ${LIBXDP_LIBRARIES} ${LIBBPF_LIBRARIES})
    target_compile_options(test-af-xdp PRIVATE -Werror -Wall -Wextra -ffunction-sections -fdata-sections)
    target_link_options(test-af-xdp PRIVATE -Wl,--gc-sections)
    add_test(NAME "TestAfXdp" COMMAND test-af-xdp)
endif()
