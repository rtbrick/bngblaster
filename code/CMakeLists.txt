include_directories("common/src/" "${CMAKE_CURRENT_BINARY_DIR}/common/src/")

add_subdirectory(common)
add_subdirectory(lwip)
add_subdirectory(bngblaster)
add_subdirectory(lspgen)

install(PROGRAMS bngblaster-cli DESTINATION bin)
install(PROGRAMS bgpupdate DESTINATION bin)
install(PROGRAMS ldpupdate DESTINATION bin)