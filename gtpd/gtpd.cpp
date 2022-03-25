#include "common/api_sock_io.h"
#include "gtpd.h"
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <cassert>

// Store pointer combined with type id in low bits in
// epoll_event::data::u64.
enum ObjType {
    OBJ_STOP_SIGNAL = 1,
    OBJ_SERVER_SOCK = 2,
    OBJ_API_SOCK = 3,
    OBJ_API_CLIENT_SOCK_RECV = 4,
    OBJ_API_CLIENT_SOCK_SEND = 5,

    OBJ_TYPE_MAX,
    OBJ_ALIGN_MIN = 8,
};
static_assert(OBJ_ALIGN_MIN >= OBJ_TYPE_MAX);

struct alignas(OBJ_ALIGN_MIN) Obj {};

static uint64_t encode_obj(ObjType t, Obj *o) {
    auto u = reinterpret_cast<uint64_t>(o);
    assert((u & (decltype(u)(1) * OBJ_ALIGN_MIN - 1)) == 0);
    return t | u;
}

static ObjType decode_type(uint64_t u) {
    return static_cast<ObjType>(u & (decltype(u)(1) * OBJ_ALIGN_MIN - 1));
}

static Obj *decode_obj(uint64_t u) {
    return reinterpret_cast<Obj *>(u & ~(decltype(u)(1) * OBJ_ALIGN_MIN - 1));
}

static uint64_t encode_uint(ObjType t, unsigned i) {
    return t | (static_cast<uint64_t>(i) * OBJ_ALIGN_MIN);
}

static unsigned decode_uint(uint64_t u) {
    return static_cast<unsigned>(u / OBJ_ALIGN_MIN);
}

struct Gtpd::ApiClient: Obj {
    ApiClient *next, **pprevnext;

    Fd sock;
    Fd inmsg_fd;
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

    epoll = Fd(epoll_create1(EPOLL_CLOEXEC));
    if (!epoll) {
        throw std::system_error(errno, std::generic_category(),
                                "epoll_create");
    }

    add_watcher(api_sock.sock, encode_uint(OBJ_API_SOCK, 0), EPOLLIN);

    signalfd = Fd(::signalfd(-1, &opts.stop_sig, SFD_CLOEXEC));
    if (!signalfd) {
        throw std::system_error(errno, std::generic_category(),
                                "signalfd");
    }

    add_watcher(signalfd, encode_uint(OBJ_STOP_SIGNAL, 0), EPOLLIN);

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
    add_watcher(server_sock,
                encode_uint(OBJ_SERVER_SOCK, server_sock.get()), EPOLLIN);
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
        epoll_event evt = {};
        if (epoll_wait(epoll.get(), &evt, 1, -1) != 1) {
            continue;
        }
        ApiClient *client;
        switch (decode_type(evt.data.u64)) {
        case OBJ_STOP_SIGNAL: return;
        case OBJ_SERVER_SOCK:
            server_sock_recv(decode_uint(evt.data.u64));
            break;
        case OBJ_API_SOCK:
            api_sock_accept();
            break;
        case OBJ_API_CLIENT_SOCK_RECV:
        case OBJ_API_CLIENT_SOCK_SEND:
            client = static_cast<ApiClient *>(decode_obj(evt.data.u64));
            api_client_state_machine(client, decode_type(evt.data.u64));
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
        add_watcher(sock, encode_obj(OBJ_API_CLIENT_SOCK_RECV, client.get()),
                    EPOLLIN | EPOLLONESHOT);
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

    case OBJ_API_CLIENT_SOCK_RECV:
            while (client->inmsg_length < len_min ||
                   client->inmsg_length <
                   std::min<decltype(client->inmsg_length)>(
                       client->inmsg.length, sizeof(client->inmsg_buf))) {

                ssize_t rc; std::tie(rc, client->inmsg_fd) = api_sock_recv(
                    client->sock,
                    client->inmsg_buf + client->inmsg_length,
                    sizeof(client->inmsg_buf) - client->inmsg_length,
                    MSG_CMSG_CLOEXEC
                );

                if (rc <= 0) {
                    if (rc == -1 && errno == EAGAIN) {
                        modify_watcher(client->sock,
                                       encode_obj(OBJ_API_CLIENT_SOCK_RECV, client),
                                       EPOLLIN | EPOLLONESHOT);
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

    case OBJ_API_CLIENT_SOCK_SEND:
                while (client->outmsg_offset != client->outmsg.length) {
                    ssize_t rc;
                    if (--send_limit == 0 || -1 == (rc = api_sock_send(
                            client->sock,
                            client->outmsg_buf + client->outmsg_offset,
                            client->outmsg.length - client->outmsg_offset,
                            client->outmsg_fd,
                            MSG_NOSIGNAL
                        )) && errno == EAGAIN
                    ) {
                        modify_watcher(client->sock,
                                       encode_obj(OBJ_API_CLIENT_SOCK_SEND,
                                                  client),
                                       EPOLLOUT | EPOLLONESHOT);
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

            client->inmsg_fd = Fd();

            client->inmsg_length -= client->inmsg.length;
            memmove(client->inmsg_buf, client->inmsg_buf + client->inmsg.length,
                    client->inmsg_length);
        }
    }
}

static void encode_next_tunnel(GtpdCore &core, GtpuTunnelId id, ApiMsg *dest) {
    id = core.next_tunnel(id);
    if (id == GtpuTunnel::fixme()) {
        auto &resp = dest->response;
        resp.length = sizeof(resp);
        resp.code = API_RESPONSE_CODE;
        resp.rc = 0;
    } else {
        auto &list_item = dest->gtpu_tunnel_list_item;
        list_item.length = sizeof(list_item);
        list_item.code = API_GTPU_TUNNEL_LIST_ITEM_CODE;

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
                GtpuTunnelId id = GtpuTunnel::fixme();
                std::tie(id, client->outmsg_fd) = core.create_tunnel(
                    GtpuTunnel(msg.tunnel), InnerProto(msg.inner_proto),
                    Cookie(msg.cookie),
                    std::move(client->inmsg_fd)
                );
                resp.rc = 0;
            }
            break;
        case API_DELETE_GTPU_TUNNEL_CODE: {
                auto &msg = client->inmsg.delete_gtpu_tunnel;
                if (client->inmsg.length != sizeof(msg)) {
                    resp.rc = -EINVAL;
                    break;
                }
                core.delete_tunnel(GtpuTunnel(msg.tunnel));
                resp.rc = 0;
            }
            break;
        case API_MODIFY_GTPU_TUNNEL_CODE: {
                auto &msg = client->inmsg.modify_gtpu_tunnel;
                if (client->inmsg.length != sizeof(msg)) {
                    resp.rc = -EINVAL;
                    break;
                }
                auto &pipe = core.gtpu_pipe(GtpuTunnelId(msg.tunnel));
                ApiGtpuTunnel tunnel = pipe.tunnel().api_gtpu_tunnel();
                InnerProto inner_proto = pipe.inner_proto();
                if (msg.flags & API_MODIFY_GTPU_TUNNEL_TUNNEL_FLAG) {
                    tunnel = msg.new_tunnel;
                }
                if (msg.flags & API_MODIFY_GTPU_TUNNEL_INNER_PROTO_FLAG) {
                    inner_proto = InnerProto(msg.new_inner_proto);
                }
                core.modify_tunnel(GtpuTunnelId(msg.tunnel), GtpuTunnel(tunnel), inner_proto);
                resp.rc = 0;
            }
            break;
        case API_LIST_GTPU_TUNNELS_CODE: {
                auto &msg = client->inmsg.list_gtpu_tunnels;
                if (client->inmsg.length != sizeof(msg)) {
                    resp.rc = -EINVAL;
                    break;
                }
                encode_next_tunnel(core, GtpuTunnel::fixme(), &client->outmsg);
            }
            break;
        }
    } catch (const std::bad_alloc &) {
        resp.rc = -ENOMEM;
    } catch (const std::system_error &e) {
        resp.rc = -e.code().value();
    }
}

bool Gtpd::api_client_serve_cont(ApiClient *client) {
    if (client->inmsg.code == API_LIST_GTPU_TUNNELS_CODE &&
        client->outmsg.code == API_GTPU_TUNNEL_LIST_ITEM_CODE) {

        auto id = GtpuTunnel(client->outmsg.gtpu_tunnel_list_item.tunnel);
        encode_next_tunnel(core, id, &client->outmsg);
        return true;
    }
    return false;
}

void Gtpd::add_watcher(const Fd &fd, uint64_t data, int events) {
    epoll_event evt = {};
    evt.events = events;
    evt.data.u64 = data;
    if (epoll_ctl(epoll.get(), EPOLL_CTL_ADD, fd.get(), &evt) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "epoll_ctl(APOLL_CTL_ADD)");
    }
}

void Gtpd::modify_watcher(const Fd &fd, uint64_t data, int events) {
    epoll_event evt = {};
    evt.events = events;
    evt.data.u64 = data;
    if (epoll_ctl(epoll.get(), EPOLL_CTL_MOD, fd.get(), &evt) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "epoll_ctl(APOLL_CTL_MOD)");
    }
}
