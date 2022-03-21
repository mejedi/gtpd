project(gtpd)
cmake_minimum_required(VERSION 3.14)
set(CMAKE_CXX_STANDARD 17)

include_directories(. include)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_library(gtpd_common STATIC
    common/api_sock_io.cpp
)

add_executable(gtpd
    gtpd/bpf.cpp
    gtpd/gtpd.cpp
    gtpd/gtpd_core.cpp
    gtpd/gtpu_pipe.cpp
    gtpd/gtpu_tunnel.cpp
    gtpd/main.cpp
    gtpd/xdp.cpp
)
target_link_libraries(gtpd gtpd_common pthread systemd)

# required for the main executable to export symbols (uprobes)
target_link_options(gtpd PRIVATE -Wl,--export-dynamic)

add_executable(gtpd_ctl 
    gtpd_ctl/api_client.cpp
    gtpd_ctl/cmdline.cpp
    gtpd_ctl/main.cpp
)
target_link_libraries(gtpd_ctl gtpd_common)

# Generate gtpd.bpftrace in the build dir for use with gtpd binary
# in the build dir.
add_custom_target(gen_gtpd_bpftrace ALL DEPENDS "gtpd.bpftrace")
add_custom_command(
    OUTPUT gtpd.bpftrace DEPENDS gtpd.bpftrace
    COMMAND sed -e 's|/usr/bin/gtpd|${CMAKE_CURRENT_BINARY_DIR}/gtpd|'
                "${CMAKE_CURRENT_SOURCE_DIR}/gtpd.bpftrace"
                > gtpd.bpftrace
)
