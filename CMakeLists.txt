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

function(expand_gtpd_bpftrace DEST GTPD_PATH)
    configure_file(gtpd.bpftrace ${DEST})
endfunction()
expand_gtpd_bpftrace(gtpd.bpftrace ${CMAKE_BINARY_DIR}/gtpd)
