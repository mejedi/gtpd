project(gtpd)
cmake_minimum_required(VERSION 3.14)
include(CheckIPOSupported)
set(CMAKE_CXX_STANDARD 17)

# build RelWithDebInfo by default; this is convenient for someone
# wishing to just build deb packages
if("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(CMAKE_CXX_VISIBILITY_PRESET hidden)

check_ipo_supported(RESULT ipo_supported LANGUAGES CXX)
function(enable_ipo_if_supported)
    if(ipo_supported)
        set_property(
            TARGET ${ARGV}
            PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        )
        set_property(
            TARGET ${ARGV}
            PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE
        )
    endif()
endfunction()

include_directories(include src)

add_library(gtpd_common STATIC
    src/common/api_sock_io.cpp
    src/common/version.cpp
)
add_custom_command(
    OUTPUT src/common/version.cpp hack_missing_file_to_make_it_run_every_build
    COMMAND "${CMAKE_SOURCE_DIR}/gen_version.sh" src/common/version.cpp
)
enable_ipo_if_supported(gtpd_common)

add_executable(gtpd
    src/gtpd/bpf.cpp
    src/gtpd/cache_line_aligned.cpp
    src/gtpd/epoll.cpp
    src/gtpd/gtpd.cpp
    src/gtpd/gtpd_core.cpp
    src/gtpd/gtpu_pipe.cpp
    src/gtpd/gtpu_tunnel.cpp
    src/gtpd/main.cpp
    src/gtpd/xdp.cpp
)
target_link_libraries(gtpd gtpd_common pthread systemd)
enable_ipo_if_supported(gtpd)

# required for the main executable to export symbols (uprobes)
target_link_options(gtpd PRIVATE -Wl,--export-dynamic)

add_executable(gtpd_ctl 
    src/gtpd_ctl/api_client.cpp
    src/gtpd_ctl/cmdline.cpp
    src/gtpd_ctl/main.cpp
)
target_link_libraries(gtpd_ctl gtpd_common)
enable_ipo_if_supported(gtpd_ctl)

# Generate gtpd.bpftrace in the build dir for use with gtpd binary
# in the build dir.
add_custom_target(gen_gtpd_bpftrace ALL DEPENDS "gtpd.bpftrace")
add_custom_command(
    OUTPUT gtpd.bpftrace DEPENDS gtpd.bpftrace
    COMMAND sed -e 's|/usr/bin/gtpd|${CMAKE_CURRENT_BINARY_DIR}/gtpd|'
                "${CMAKE_CURRENT_SOURCE_DIR}/gtpd.bpftrace"
                > gtpd.bpftrace
)

install(TARGETS gtpd gtpd_ctl
        DESTINATION /usr/bin
        COMPONENT gtpd)

install(FILES systemd/gtpd.service systemd/gtpd.socket
        DESTINATION /lib/systemd/system
        COMPONENT gtpd)

install(FILES systemd/gtpd.conf
        DESTINATION /etc
        COMPONENT gtpd)

install(DIRECTORY include/gtpd
        TYPE INCLUDE
        COMPONENT gtpd_dev)

set(CPACK_GENERATOR "DEB")
configure_file(package.cmake package.cmake @ONLY)
set(CPACK_PROPERTIES_FILE package.cmake)
include(CPack)
