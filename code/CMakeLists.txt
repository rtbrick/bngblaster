include_directories("common/src/")

add_subdirectory(common)
add_subdirectory(lwip)
add_subdirectory(bngblaster)
add_subdirectory(lspgen)

install(PROGRAMS bngblaster-cli DESTINATION sbin)
install(PROGRAMS bgpupdate DESTINATION bin)