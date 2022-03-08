include_directories("common/src/")

add_subdirectory(common)
add_subdirectory(bngblaster)
add_subdirectory(lspgen)

install(PROGRAMS bngblaster-cli DESTINATION sbin)
