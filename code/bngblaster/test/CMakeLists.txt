include_directories("../src/")

# Disable LWIP for unit tests 
remove_definitions(-DBNGBLASTER_LWIP)

set(LINK_LIBS ${libdict} cmocka pcap m)

add_executable(test-protocols protocols.c ../src/bbl_protocols.c)
target_link_libraries(test-protocols ${LINK_LIBS})
target_compile_options(test-protocols PRIVATE -Werror -Wall -Wextra)
add_test(NAME "TestProtocols" COMMAND test-protocols)

if(BNGBLASTER_AF_XDP)
    add_executable(test-af-xdp-ring af_xdp_ring.c)
    target_include_directories(test-af-xdp-ring PRIVATE $<TARGET_PROPERTY:bngblaster,INCLUDE_DIRECTORIES>)
    target_compile_definitions(test-af-xdp-ring PRIVATE $<TARGET_PROPERTY:bngblaster,COMPILE_DEFINITIONS>)
    target_compile_options(test-af-xdp-ring PRIVATE -UNDEBUG -ffunction-sections -fdata-sections)
    target_link_options(test-af-xdp-ring PRIVATE -Wl,--gc-sections)
    add_test(NAME "TestAfXdpRing" COMMAND test-af-xdp-ring)
endif()

add_executable(test-decode-pcap protocols_decode_pcap.c ../src/bbl_protocols.c)
target_link_libraries(test-decode-pcap ${LINK_LIBS})
target_compile_options(test-decode-pcap PRIVATE -Werror -Wall -Wextra)