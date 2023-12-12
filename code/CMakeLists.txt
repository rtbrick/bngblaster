include_directories("common/src/")
include_directories("libdict/include/")

add_subdirectory(common)
add_subdirectory(lwip)
add_subdirectory(libdict)
add_subdirectory(bngblaster)
add_subdirectory(lspgen)

install(PROGRAMS bngblaster-cli DESTINATION sbin)
install(PROGRAMS bgpupdate DESTINATION bin)
install(PROGRAMS ldpupdate DESTINATION bin)