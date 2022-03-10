#pragma once
#include "gtpu_tunnel.h"
#include "gtpu_pipe.h"
#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <signal.h>
#include <vector>

class GtpdCore {
public:
    struct Delegate {
        virtual GtpuTunnelDispatcher *tunnel_dispatcher(AF address_family) noexcept = 0;
        virtual void replace_tunnel_dispatcher(AF address_family,
                                               std::unique_ptr<GtpuTunnelDispatcher>) = 0;
    };

    Fd create_gtpu_tunnel(const ApiCreateGtpuTunnelMsg &msg, Fd xdp_sock);
    void delete_gtpu_tunnel(const ApiDeleteGtpuTunnelMsg &msg);
    void modify_gtpu_tunnel(const ApiModifyGtpuTunnelMsg &msg);

    std::optional<ApiGtpuTunnelListItemMsg>
    list_gtpu_tunnels_next(const ApiListGtpuTunnelsMsg &msg,
                           const ApiGtpuTunnel *cur);

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
    struct Watcher;
    struct Session;

private:
    Delegate * const delegate;
    const Options options;
    const Fd epoll;
    std::map<std::u32string_view, std::unique_ptr<Session>> sessions;
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

    int watcher_epoll_ctl(int op, Watcher);

    void add_watcher(Watcher);
    void delete_watcher(Watcher) noexcept;
    void update_watcher(Watcher) noexcept;

    void worker_proc(Worker &);
    void interrupt_workers(Interrupt);
    void sync_with_workers();
    void stop_workers();

    void modify_session_socket_and_bpf_maps(Session* sess, const GtpuTunnel &new_tunnel);
};
