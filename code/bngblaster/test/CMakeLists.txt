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

    add_executable(test-af-xdp-restore af_xdp_restore.c)
    target_include_directories(test-af-xdp-restore PRIVATE $<TARGET_PROPERTY:bngblaster,INCLUDE_DIRECTORIES>)
    target_compile_definitions(test-af-xdp-restore PRIVATE $<TARGET_PROPERTY:bngblaster,COMPILE_DEFINITIONS>)
    target_compile_options(test-af-xdp-restore PRIVATE -UNDEBUG -ffunction-sections -fdata-sections)
    target_link_options(test-af-xdp-restore PRIVATE -Wl,--gc-sections)
    target_link_libraries(test-af-xdp-restore ${LIBXDP_LIBRARIES} ${LIBBPF_LIBRARIES})
    foreach(scenario expand shrink unchanged separate-expand separate-shrink
                     channels-fail rss-fail clamp-fail preserve rebalance handles
                     setup-expand setup-shrink)
        add_test(NAME "TestAfXdpRestore-${scenario}" COMMAND test-af-xdp-restore ${scenario})
    endforeach()
endif()

add_executable(test-decode-pcap protocols_decode_pcap.c ../src/bbl_protocols.c)
target_link_libraries(test-decode-pcap ${LINK_LIBS})
target_compile_options(test-decode-pcap PRIVATE -Werror -Wall -Wextra)