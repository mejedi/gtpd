#pragma once
#include "common/fd.h"
#include "common/api_sock_io.h"
#include "gtpd/api.h"
#include <string_view>

struct ApiClient {
    ApiClient(std::string_view path);

    std::pair<uint32_t, Fd>
    create_gtpu_tunnel(const ApiCreateGtpuTunnelMsg &msg, const Fd &xdp_sock,
                       const Fd &session_leader_pidfd);
    void delete_gtpu_tunnel(const ApiDeleteGtpuTunnelMsg &msg);
    void modify_gtpu_tunnel(const ApiModifyGtpuTunnelMsg &msg);

    std::vector<ApiGtpuTunnelListItemMsg>
    list_gtpu_tunnels(const ApiListGtpuTunnelsMsg &msg);

private:
    Fd sock;
    union {
        ApiMsg reply;
        uint8_t reply_buf[sizeof(reply)];
    };
    size_t reply_size = 0;

private:
    static Fd connect(std::string_view path);
    void send_request(const void *req, size_t reqlen, FdPtrs = FdPtrs());
    Fds receive_reply();
    uint32_t verify_response();
};
