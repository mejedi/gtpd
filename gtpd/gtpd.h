#pragma once
#include "gtpd_core.h"
#include "epoll.h"
#include <sys/socket.h>
#include <sys/un.h>

class Gtpd: private GtpdCore::Delegate {
public:
    struct Options: GtpdCore::Options {
        // int encap_mtu
        // int batch_size
        // int xdp_pool_size
        // int nworkers
        // int interrupt_sig
        bool enable_ip = false;
        bool enable_ip6 = false;
        int api_sock_fd = -1;
        std::string_view api_sock_path;
        int api_sock_backlog = 10;
        sigset_t stop_sig = {};
    // Assumptions irt. signals:
    //  * interrupt_sig is NOT blocked and a handler is already installed;
    //  * stop_sig(s) are blocked.
    };

    Gtpd(const Options &opts);

    ~Gtpd();

    // run until a signal is delivered (Options::stop_sig).
    void run();

private:
    // This is to reliably unlink the listening socket even if Gtpd ctor
    // throws.
    struct ApiSock {
        Fd sock;
        sockaddr_un addr = {};

        ApiSock(Fd fd, std::string_view path, int backlog);

        ~ApiSock();
    };

    struct ApiClient;
    struct WatcherInfo;

private:
    Epoll<WatcherInfo> epoll;
    Fd signalfd;

    Fd server_sock, server_sock6;
    SocketRegistration server_sock_reg, server_sock6_reg;
    std::unique_ptr<GtpuTunnelDispatcher> dispatcher, dispatcher6;

    ApiSock api_sock;
    ApiClient *api_client = nullptr;

    GtpdCore core;

    std::array<EpollEvent<WatcherInfo>, 16> events;

private:
    std::unique_ptr<GtpuTunnelDispatcher> &tunnel_dispatcher_ref(AF address_family) {
        switch (address_family) {
        case AF::INET: return dispatcher;
        case AF::INET6: return dispatcher6;
        }
        __builtin_unreachable();
    }

    Fd &server_sock_ref(AF address_family) {
        switch (address_family) {
        case AF::INET: return server_sock;
        case AF::INET6: return server_sock6;
        }
        __builtin_unreachable();
    }

    SocketRegistration &server_sock_reg_ref(AF address_family) {
        switch (address_family) {
        case AF::INET: return server_sock_reg;
        case AF::INET6: return server_sock6_reg;
        }
        __builtin_unreachable();
    }

    GtpuTunnelDispatcher *tunnel_dispatcher(AF address_family) noexcept override {
        return tunnel_dispatcher_ref(address_family).get();
    }

    void replace_tunnel_dispatcher(AF address_family,
                                   std::unique_ptr<GtpuTunnelDispatcher> disp) override {
        assert(tunnel_dispatcher_ref(address_family) && "address family enabled");
        disp->activate(server_sock_ref(address_family),
                      server_sock_reg_ref(address_family));
        tunnel_dispatcher_ref(address_family) = std::move(disp);
    }

    void register_session_leader(GtpuTunnelId, const Fd &) override;
    void unregister_session_leader(GtpuTunnelId, const Fd &) override;

    void enable(AF address_family);

    void server_sock_recv(int fd);
    void api_sock_accept();
    void api_client_terminate(ApiClient *client);
    void api_client_state_machine(ApiClient *client, int s);
    void api_client_serve(ApiClient *client);
    bool api_client_serve_cont(ApiClient *client);

    friend epoll_data_t encode(WatcherInfo);
    friend WatcherInfo decode(WatcherInfo, epoll_data_t);
};
