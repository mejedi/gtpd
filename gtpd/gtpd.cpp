#include "common/api_sock_io.h"
#include "gtpd.h"
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <cassert>

struct Gtpd::ApiClient {
    ApiClient *next, **pprevnext;

    Fd sock;
    Fds inmsg_fds;
    Fd outmsg_fd;

    uint32_t inmsg_length = 0;
    uint32_t outmsg_offset;

    // Input
    union {
        ApiMsg  inmsg;
        uint8_t inmsg_buf[std::max<size_t>(sizeof(inmsg), 512)];
    };

    // Output
    union {
        ApiMsg  outmsg;
        uint8_t outmsg_buf[sizeof(outmsg)];
    };
};

enum class WatcherType {
    TERM_SIGNAL = 1,
    SERVER_SOCK = 2,
    API_SOCK = 3,
    API_CLIENT_SOCK_RECV = 4,
    API_CLIENT_SOCK_SEND = 5,
    SESS_LEADER = 6,

    MAX,
};
static constexpr int PTR_ALIGN_MIN = 8;
static_assert(PTR_ALIGN_MIN >= int(WatcherType::MAX));

struct Gtpd::WatcherInfo {
    WatcherType type;
    union {
        int fd;
        GtpuTunnelId id;
        Gtpd::ApiClient *client;

        uint32_t u32_;
        uintptr_t uptr_;
    };
};

epoll_data_t encode(Gtpd::WatcherInfo info) {
    switch (info.type) {
    case WatcherType::SERVER_SOCK:
    case WatcherType::SESS_LEADER:
        static_assert(sizeof(info.fd) == sizeof(info.u32_));
        static_assert(sizeof(info.id) == sizeof(info.u32_));
        return { .u64 = uint64_t(info.type) | (PTR_ALIGN_MIN * uint64_t(info.u32_)) };
    case WatcherType::API_CLIENT_SOCK_RECV:
    case WatcherType::API_CLIENT_SOCK_SEND:
        static_assert(sizeof(info.client) == sizeof(info.uptr_));
        static_assert(alignof(Gtpd::ApiClient) >= PTR_ALIGN_MIN);
        assert((info.uptr_ & (PTR_ALIGN_MIN - 1)) == 0);
        return { .u64 = uint64_t(info.type) | info.uptr_ };
    default:
        return { .u64 = uint64_t(info.type) };
    }
}

Gtpd::WatcherInfo decode(Gtpd::WatcherInfo, epoll_data_t data) {
    constexpr uintptr_t M = PTR_ALIGN_MIN - 1;
    auto t = WatcherType(data.u64 & M);
    switch (t) {
    case WatcherType::SERVER_SOCK:
    case WatcherType::SESS_LEADER:
        return { .type = t, .u32_ = uint32_t(data.u64 / PTR_ALIGN_MIN) };
    case WatcherType::API_CLIENT_SOCK_RECV:
    case WatcherType::API_CLIENT_SOCK_SEND:
        return { .type = t, .uptr_ = data.u64 & ~M };
    default:
        return { .type = t };
    }
}

static Fd api_sock(const sockaddr_un &addr, int backlog) {
    Fd fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (!fd) return {};
    while (bind(fd.get(), reinterpret_cast<const sockaddr *>(&addr),
                sizeof(addr)) != 0) {
        if (errno != EADDRINUSE || unlink(addr.sun_path) != 0) return {};
    }
    if (listen(fd.get(), backlog) != 0) return {};
    return fd;
}

Gtpd::ApiSock::ApiSock(Fd fd, std::string_view path, int backlog) {
    if (fd) {
        addr.sun_family = 0;
        sock = std::move(fd);
        return;
    }
    if (path.size() >= sizeof(addr) - offsetof(sockaddr_un, sun_path))
        throw std::runtime_error("API socket path too long");
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path.data(), path.size());

    sock = ::api_sock(addr, backlog);
    if (!sock) throw std::system_error(errno, std::generic_category(),
                                        "Creating API socket");
}

Gtpd::ApiSock::~ApiSock() {
    if (addr.sun_family) unlink(addr.sun_path);
}

Gtpd::Gtpd(const Options &opts)
    : api_sock(Fd(opts.api_sock_fd), opts.api_sock_path, opts.api_sock_backlog),
      core(this, opts) {

    epoll.add_watcher({ api_sock.sock, EPOLLIN, WatcherInfo{ .type = WatcherType::API_SOCK } });

    signalfd = Fd(::signalfd(-1, &opts.stop_sig, SFD_CLOEXEC));
    if (!signalfd) {
        throw std::system_error(errno, std::generic_category(),
                                "signalfd");
    }

    epoll.add_watcher({ signalfd, EPOLLIN, WatcherInfo{ .type = WatcherType::TERM_SIGNAL } });

    if (opts.enable_ip) enable(AF::INET);
    if (opts.enable_ip6) enable(AF::INET6);
}

void Gtpd::enable(AF address_family) {
    auto &server_sock = server_sock_ref(address_family);
    auto &server_sock_reg = server_sock_reg_ref(address_family);
    auto &tunnel_dispatcher = tunnel_dispatcher_ref(address_family);

    server_sock = gtpu_socket(address_family);
    server_sock_reg = SocketRegistration(server_sock);
    tunnel_dispatcher = GtpuTunnelDispatcher::create(address_family);
    tunnel_dispatcher->activate(server_sock, server_sock_reg);

    int level = 0, optname = 0, t = 1;
    switch (address_family) {
    case AF::INET:
        level = IPPROTO_IP; optname = IP_PKTINFO;
        break;
    case AF::INET6:
        level = IPPROTO_IPV6; optname = IPV6_RECVPKTINFO;
        break;
    }
    if (setsockopt(server_sock.get(), level, optname, &t, sizeof(t)) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "Configure GTPU socket");
    }

#if 0
    epoll.add_watcher({
        server_sock, EPOLLIN,
        WatcherInfo{ .type = WatcherType::SERVER_SOCK, .fd = server_sock.get() }
    });
#endif
}

Gtpd::~Gtpd() {
    auto *p = api_client;
    while (p) {
        auto *client = p;
        p = p->next;
        delete(client);
    }
}

void Gtpd::run() {
    for (;;) {
        EpollEvent<WatcherInfo> event;
        if (epoll.pwait(&event, 1, -1) != 1) {
            continue;
        }
        auto info = event.data();
        switch (info.type) {
        case WatcherType::TERM_SIGNAL: return;
        case WatcherType::SERVER_SOCK:
            server_sock_recv(info.fd);
            break;
        case WatcherType::API_SOCK:
            api_sock_accept();
            break;
        case WatcherType::API_CLIENT_SOCK_RECV:
        case WatcherType::API_CLIENT_SOCK_SEND:
            api_client_state_machine(info.client, int(info.type));
            break;
        case WatcherType::SESS_LEADER:
            core.delete_tunnel(info.id);
            break;
        default:
            break;
        }
    }
}

void Gtpd::server_sock_recv(int fd) {
}

void Gtpd::api_sock_accept() {
    Fd sock(accept4(api_sock.sock.get(), nullptr, nullptr,
                    SOCK_NONBLOCK | SOCK_CLOEXEC));
    if (!sock) return;
    try {
        auto client = std::make_unique<ApiClient>();
        epoll.add_watcher({
            sock, EPOLLIN | EPOLLONESHOT,
            WatcherInfo{ .type = WatcherType::API_CLIENT_SOCK_RECV, .client = client.get() }
        });
        client->sock = std::move(sock);
        client->pprevnext = &api_client;
        client->next = api_client;
        if (api_client) api_client->pprevnext = &client->next;
        api_client = client.release();
    } catch (const std::exception &e) {
    }
}

void Gtpd::api_client_terminate(ApiClient *client) {
    *client->pprevnext = client->next;
    if (client->next) client->next->pprevnext = client->pprevnext;
    delete(client);
}

void Gtpd::api_client_state_machine(ApiClient *client, int s) {

    constexpr size_t len_min = offsetof(ApiResponseMsg, rc); // code + length

    int send_limit = 16; // How many messages we send before yielding.

    switch (s) {
        for (;;) {

    case int(WatcherType::API_CLIENT_SOCK_RECV):
            while (client->inmsg_length < len_min ||
                   client->inmsg_length <
                   std::min<decltype(client->inmsg_length)>(
                       client->inmsg.length, sizeof(client->inmsg_buf))) {

                ssize_t rc; std::tie(rc, client->inmsg_fds) = api_sock_recv(
                    client->sock,
                    client->inmsg_buf + client->inmsg_length,
                    sizeof(client->inmsg_buf) - client->inmsg_length,
                    MSG_CMSG_CLOEXEC
                );

                if (rc <= 0) {
                    if (rc == -1 && errno == EAGAIN) {
                        epoll.modify_watcher({
                            client->sock, EPOLLIN | EPOLLONESHOT,
                            WatcherInfo{ .type = WatcherType::API_CLIENT_SOCK_RECV, .client = client }
                        });
                    } else {
                        api_client_terminate(client);
                    }
                    return;
                }

                client->inmsg_length += rc;
            }

            // Message too long?
            if (client->inmsg.length > sizeof(client->inmsg_buf))
                return api_client_terminate(client);

            api_client_serve(client);

            do {
                client->outmsg_offset = 0;

    case int(WatcherType::API_CLIENT_SOCK_SEND):
                while (client->outmsg_offset != client->outmsg.length) {
                    ssize_t rc;
                    if (--send_limit == 0 || -1 == (rc = api_sock_send(
                            client->sock,
                            client->outmsg_buf + client->outmsg_offset,
                            client->outmsg.length - client->outmsg_offset,
                            FdPtrs{ &client->outmsg_fd },
                            MSG_NOSIGNAL
                        )) && errno == EAGAIN
                    ) {
                        epoll.modify_watcher({
                            client->sock, EPOLLOUT | EPOLLONESHOT,
                            WatcherInfo{ .type = WatcherType::API_CLIENT_SOCK_SEND, .client = client }
                        });
                        return;
                    }

                    if (rc == -1) {
                        api_client_terminate(client);
                        return;
                    }

                    client->outmsg_offset += rc;
                    client->outmsg_fd = Fd();
                }
            } while (api_client_serve_cont(client));

            client->inmsg_fds = Fds();

            client->inmsg_length -= client->inmsg.length;
            memmove(client->inmsg_buf, client->inmsg_buf + client->inmsg.length,
                    client->inmsg_length);
        }
    }
}

static void encode_next_tunnel(GtpdCore &core, GtpuTunnelId id, ApiMsg *dest) {
    id = core.next_tunnel(id);
    if (id == GtpuTunnelId(0)) {
        auto &resp = dest->response;
        resp.length = sizeof(resp);
        resp.code = API_RESPONSE_CODE;
        resp.rc = 0;
    } else {
        auto &list_item = dest->gtpu_tunnel_list_item;
        list_item.length = sizeof(list_item);
        list_item.code = API_GTPU_TUNNEL_LIST_ITEM_CODE;
        list_item.id = uint32_t(id);

        auto const &pipe = core.gtpu_pipe(id);
        list_item.tunnel = pipe.tunnel().api_gtpu_tunnel();
        list_item.inner_proto = uint32_t(pipe.inner_proto());
        list_item.halt = core.halt_code(id);
        list_item.cookie = uint32_t(pipe.cookie());
        list_item.encap_ok = pipe.encap_ok();
        list_item.encap_drop_rx = pipe.encap_drop_rx();
        list_item.encap_drop_tx = pipe.encap_drop_tx();
        list_item.decap_ok = pipe.decap_ok();
        list_item.decap_drop_rx = pipe.decap_drop_rx();
        list_item.decap_drop_tx = pipe.decap_drop_tx();
        list_item.decap_bad = pipe.decap_bad();
        list_item.decap_trunc = pipe.decap_trunc();
    }
}

void Gtpd::api_client_serve(ApiClient *client) {

    auto &resp = client->outmsg.response;
    resp.length = sizeof(resp);
    resp.code = API_RESPONSE_CODE;
    try {
        switch (client->inmsg.code) {
        default:
            resp.rc = -EINVAL;
            break;
        case API_CREATE_GTPU_TUNNEL_CODE: {
                auto &msg = client->inmsg.create_gtpu_tunnel;
                if (client->inmsg.length != sizeof(msg)) {
                    resp.rc = -EINVAL;
                    break;
                }
                GtpuTunnelId id;
                std::tie(id, client->outmsg_fd) = core.create_tunnel(
                    GtpuTunnel(msg.tunnel), InnerProto(msg.inner_proto),
                    Cookie(msg.cookie),
                    std::move(client->inmsg_fds[0]),
                    std::move(client->inmsg_fds[1])
                );
                resp.rc = uint32_t(id);
            }
            break;
        case API_DELETE_GTPU_TUNNEL_CODE: {
                auto &msg = client->inmsg.delete_gtpu_tunnel;
                if (client->inmsg.length != sizeof(msg)) {
                    resp.rc = -EINVAL;
                    break;
                }
                core.delete_tunnel(GtpuTunnelId(msg.id));
                resp.rc = 0;
            }
            break;
        case API_MODIFY_GTPU_TUNNEL_CODE: {
                auto &msg = client->inmsg.modify_gtpu_tunnel;
                if (client->inmsg.length != sizeof(msg)) {
                    resp.rc = -EINVAL;
                    break;
                }
                auto &pipe = core.gtpu_pipe(GtpuTunnelId(msg.id));

                ApiGtpuTunnel tunnel = pipe.tunnel().api_gtpu_tunnel();
                static constexpr auto lar_mask =
                    API_MODIFY_GTPU_TUNNEL_LOCAL_FLAG | API_MODIFY_GTPU_TUNNEL_REMOTE_FLAG;
                if (auto fl = msg.flags & lar_mask) {
                    if (fl != lar_mask
                        && tunnel.address_family != msg.new_tunnel.address_family
                    ) {
                        resp.rc = -EINVAL;
                        break;
                    }
                    tunnel.address_family = msg.new_tunnel.address_family;
                    if (msg.flags & API_MODIFY_GTPU_TUNNEL_LOCAL_FLAG)
                        tunnel.local = msg.new_tunnel.local;
                    if (msg.flags & API_MODIFY_GTPU_TUNNEL_REMOTE_FLAG)
                        tunnel.remote = msg.new_tunnel.remote;
                }
                if (msg.flags & API_MODIFY_GTPU_TUNNEL_LOCAL_TEID_FLAG) {
                    tunnel.local_teid = msg.new_tunnel.local_teid;
                }
                if (msg.flags & API_MODIFY_GTPU_TUNNEL_REMOTE_TEID_FLAG) {
                    tunnel.remote_teid = msg.new_tunnel.remote_teid;
                }

                InnerProto inner_proto = pipe.inner_proto();
                if (msg.flags & API_MODIFY_GTPU_TUNNEL_INNER_PROTO_FLAG) {
                    inner_proto = InnerProto(msg.new_inner_proto);
                }

                core.modify_tunnel(GtpuTunnelId(msg.id), GtpuTunnel(tunnel), inner_proto);
                resp.rc = 0;
            }
            break;
        case API_LIST_GTPU_TUNNELS_CODE: {
                auto &msg = client->inmsg.list_gtpu_tunnels;
                if (client->inmsg.length != sizeof(msg)) {
                    resp.rc = -EINVAL;
                    break;
                }
                encode_next_tunnel(core, GtpuTunnelId(0), &client->outmsg);
            }
            break;
        }
    } catch (const std::bad_alloc &) {
        resp.rc = -ENOMEM;
    } catch (const std::system_error &e) {
        resp.rc = -e.code().value();
    }
}

void Gtpd::register_session_leader(GtpuTunnelId tunnel_id, const Fd &pidfd) {
    if (!pidfd) return;
    epoll.add_watcher({
        pidfd, EPOLLIN,
        WatcherInfo{ .type = WatcherType::SESS_LEADER, .id = tunnel_id }
    });
}

void Gtpd::unregister_session_leader(const Fd &pidfd) {
    if (!pidfd) return;
    epoll.delete_watcher({ pidfd });
}

bool Gtpd::api_client_serve_cont(ApiClient *client) {
    if (client->inmsg.code == API_LIST_GTPU_TUNNELS_CODE &&
        client->outmsg.code == API_GTPU_TUNNEL_LIST_ITEM_CODE) {

        auto id = GtpuTunnelId(client->outmsg.gtpu_tunnel_list_item.id);
        encode_next_tunnel(core, id, &client->outmsg);
        return true;
    }
    return false;
}
