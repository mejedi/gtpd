#pragma once
#include "gtpu_tunnel.h"
#include "gtpu_pipe.h"
#include "epoll.h"
#include <atomic>
#include <condition_variable>
#include <unordered_map>
#include <mutex>
#include <signal.h>
#include <vector>

// Opaque integer id; zero is invalid.
enum class GtpuTunnelId: uint32_t {};

class GtpdCore {
public:
    struct Delegate {
        virtual GtpuTunnelDispatcher *tunnel_dispatcher(AF address_family) noexcept = 0;
        virtual void replace_tunnel_dispatcher(AF address_family,
                                               std::unique_ptr<GtpuTunnelDispatcher>) = 0;

        virtual void register_session_leader(GtpuTunnelId, const Fd &) = 0;
        virtual void unregister_session_leader(const Fd &) = 0;
    };

    std::pair<GtpuTunnelId, Fd> create_tunnel(GtpuTunnel, InnerProto,
                                              Cookie, Fd xdp_sock,
                                              Fd session_leader_pidfd);
    void delete_tunnel(GtpuTunnelId);
    void modify_tunnel(GtpuTunnelId, GtpuTunnel, InnerProto);
    GtpuTunnelId next_tunnel(GtpuTunnelId);
    const GtpuPipe &gtpu_pipe(GtpuTunnelId);
    int halt_code(GtpuTunnelId);

    struct Options: GtpuPipe::Options {
        // int encap_mtu
        // int batch_size
        // int xdp_pool_size
        int nworkers = 1;              // number of workers to start
        int interrupt_sig = -1;        // signal used to alert workers
    };

    GtpdCore(Delegate *delegate, const Options &options);
    ~GtpdCore();

private:
    enum class Interrupt;
    struct Worker;
    struct WatcherInfo;
    struct Session;

    Session &session_by_id(GtpuTunnelId id);

private:
    Delegate * const delegate;
    const Options options;
    Epoll<WatcherInfo> epoll;
    std::vector<std::unique_ptr<Session>> sessions;
    std::unordered_map<std::u32string_view, Session *> session_by_key;
    std::vector<Worker> workers;

    struct {
        std::atomic<int> counter = 0;
        std::mutex mutex;
        std::condition_variable cv;
    } interrupt_barrier;

    sigset_t sigset_initial;

private:
    void ensure_address_family_enabled(AF address_family) const;
    void register_tunnel(const GtpuTunnel &tunnel, const SocketRegistration &reg);

    void unregister_tunnel(const GtpuTunnel &tunnel) noexcept {
        delegate->tunnel_dispatcher(tunnel.address_family())->unregister_tunnel(tunnel);
    }

    void worker_proc(Worker &);
    void interrupt_workers(Interrupt);
    void sync_with_workers();
    void stop_workers();

    void modify_session_socket_and_bpf_maps(Session &sess, const GtpuTunnel &new_tunnel);

    friend epoll_data_t encode(WatcherInfo);
    friend WatcherInfo decode(WatcherInfo, epoll_data_t);
};
