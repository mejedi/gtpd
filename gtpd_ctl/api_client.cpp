#include "api_client.h"
#include "common/api_sock_io.h"
#include <system_error>
#include <sys/socket.h>
#include <sys/un.h>

static const char err_invalid_response[] = "Invalid response from gtpd";

ApiClient::ApiClient(std::string_view path): sock(connect(path)) {
    if (!sock)
        throw std::system_error(errno, std::generic_category(),
                                std::string("Connecting to '")
                                + path.data() + "'");
}

Fd ApiClient::create_gtpu_tunnel(const ApiCreateGtpuTunnelMsg &msg,
                                 const Fd &xdp_sock) {
    send_request(&msg, msg.length, xdp_sock);
    Fd bpf_prog = receive_reply();
    verify_response();
    return bpf_prog;
}

void ApiClient::delete_gtpu_tunnel(const ApiDeleteGtpuTunnelMsg &msg) {
    send_request(&msg, msg.length);
    receive_reply();
    verify_response();
}

void ApiClient::modify_gtpu_tunnel(const ApiModifyGtpuTunnelMsg &msg) {
    send_request(&msg, msg.length);
    receive_reply();
    verify_response();
}

std::vector<ApiGtpuTunnelListItemMsg>
ApiClient::list_gtpu_tunnels(const ApiListGtpuTunnelsMsg &msg) {
    std::vector<ApiGtpuTunnelListItemMsg> res;
    send_request(&msg, msg.length);
    for (;;) {
        receive_reply();
        if (reply.code != API_GTPU_TUNNEL_LIST_ITEM_CODE
            || reply.length < sizeof(reply.gtpu_tunnel_list_item)
        ) {
            verify_response();
            break;
        }
        res.push_back(reply.gtpu_tunnel_list_item);
    }
    // Sort as binary strings
    std::sort(res.begin(), res.end(), [] (const ApiGtpuTunnelListItemMsg &l,
                                          const ApiGtpuTunnelListItemMsg &r
                                         ) -> bool const {
        using U8StringView = std::basic_string_view<uint8_t>;
        return U8StringView(reinterpret_cast<const uint8_t *>(&l),
                            sizeof(l))
                < U8StringView(reinterpret_cast<const uint8_t *>(&r),
                                sizeof(r));
    });
    return res;
}

Fd ApiClient::connect(std::string_view path) {
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    size_t addr_len = offsetof(sockaddr_un, sun_path) + path.size() + 1;
    if (addr_len > sizeof(addr)) {
        errno = ENAMETOOLONG;
        return {};
    }
    memcpy(addr.sun_path, path.data(), path.size());
    Fd sock(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (::connect(sock.get(),
                    reinterpret_cast<sockaddr *>(&addr), addr_len) != 0)
        return {};
    return sock;
}

void ApiClient::send_request(const void *req, size_t reqlen, const Fd& fd) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(req);
    size_t reqoff = 0;
    while (reqoff != reqlen) {
        auto rc = api_sock_send(sock, p + reqoff, reqlen - reqoff,
                                reqoff ? static_cast<const Fd&>(Fd()) : fd,
                                MSG_NOSIGNAL);
        if (rc == -1) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(),
                                    err_invalid_response);
        }

        reqoff += rc;
    }
}

Fd ApiClient::receive_reply() {
    constexpr size_t len_min = offsetof(decltype(reply), length)
                                + sizeof(reply.length);

    Fd fd;

    size_t sz = 0;
    if (reply_size) {
        // reply_buf contains reply_size bytes, made up of the
        // previous message + a portion of the current one
        if (reply.length > reply_size)
            throw std::runtime_error(err_invalid_response);
        sz = reply_size - reply.length;
        memmove(reply_buf, reply_buf + reply.length, sz);
    }

    while (sz < len_min || sz < std::min<size_t>(reply.length,
                                                    sizeof(reply_buf))
    ) {
        ssize_t rc; std::tie(rc, fd) = api_sock_recv(
            sock, reply_buf + sz, sizeof(reply_buf) - sz,
            MSG_CMSG_CLOEXEC
        );

        if (rc == 0) throw std::runtime_error(err_invalid_response);
        if (rc == -1) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(),
                                    err_invalid_response);
        }

        sz += rc;
    }
    reply_size = sz;
    return fd;
}

void ApiClient::verify_response() {
    if (reply.code != API_RESPONSE_CODE
        || reply.length < sizeof(reply.response)
    ) throw std::runtime_error(err_invalid_response);
    if (reply.response.rc != 0)
        throw std::system_error(-reply.response.rc,
                                std::generic_category(), "gtpd");
}
