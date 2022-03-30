#include "gtpd_core.h"
#include "gtpu_pipe.h"

#include <sys/epoll.h>
#include <system_error>
#include <thread>

namespace {

template <typename T>
struct on_scope_exit {
    explicit on_scope_exit(T&& fn_): fn(std::forward<T&&>(fn_)) {}
    ~on_scope_exit() { fn(); }
private:
    T fn;
};

template <typename T>
struct on_failure {
    explicit on_failure(T&& fn_): fn(std::forward<T&&>(fn_)) {}
    ~on_failure() { if (c != std::uncaught_exceptions()) fn(); }
private:
    T fn;
    int c = std::uncaught_exceptions();
};

} // namespace {

enum class GtpdCore::Interrupt { NONE, SYNC, EXIT };

struct GtpdCore::Worker {
    std::atomic<Interrupt> interrupt = Interrupt::NONE;
    Epoll<WatcherInfo> epoll;
    std::thread thread;
};

struct GtpdCore::Session {
    std::atomic_int halt = 0;
    int encap_worker_index = -1;
    int decap_worker_index = -1;
    SocketRegistration net_sock_reg;
    Fd session_leader_pidfd;
    GtpuPipe pipe;

    explicit Session(const GtpuTunnel &tun, Fd net_sock, Fd xdp_sock,
                     InnerProto inner_proto,
                     Cookie cookie,
                     const GtpdCore::Options &opts,
                     GtpuPipe::BpfState bpf_state):
        net_sock_reg(net_sock),
        pipe(tun, std::move(net_sock), std::move(xdp_sock), inner_proto, cookie, opts,
             std::move(bpf_state)) {}

    EpollWatcherInfo<WatcherInfo> net_sock_watcher();
    EpollWatcherInfo<WatcherInfo> xdp_sock_watcher();
};

namespace{
enum class WatcherType {
    NET_SOCK = 1,
    XDP_SOCK = 2,

    MAX
};
}
static constexpr int PTR_ALIGN_MIN = 4;
static_assert(int(WatcherType::MAX) <= PTR_ALIGN_MIN);

struct GtpdCore::WatcherInfo {
    WatcherType type = WatcherType(0);
    GtpdCore::Session *sess;
};

epoll_data_t encode(GtpdCore::WatcherInfo wi) {
    static_assert(alignof(GtpdCore::Session) >= PTR_ALIGN_MIN);
    return epoll_data_t{ .u64 = reinterpret_cast<uintptr_t>(wi.sess) | int(wi.type) };
}

GtpdCore::WatcherInfo decode(GtpdCore::WatcherInfo, epoll_data_t data) {
    constexpr uintptr_t M = PTR_ALIGN_MIN - 1;
    return {
        static_cast<WatcherType>(data.u64 & M),
        reinterpret_cast<GtpdCore::Session *>(data.u64 & ~M)
    };
}

std::pair<GtpuTunnelId, Fd>
GtpdCore::create_tunnel(GtpuTunnel tunnel, InnerProto inner_proto,
                        Cookie cookie, Fd xdp_sock,
                        Fd session_leader_pidfd) {

    // Find spare id
    assert(!sessions.empty());
    if (sessions.back()) sessions.resize(sessions.size() + 1);
    uint32_t id = 1;
    while (sessions[id]) ++id;
    assert(id < sessions.size());

    const AF address_family = tunnel.address_family();
    ensure_address_family_enabled(address_family);

    GtpuPipe::BpfState bpf_state;
    Fd xdp_bpf_prog = GtpuPipe::xdp_bpf_prog(xdp_sock, bpf_state);

    auto p = std::make_unique<Session>(tunnel,
                                       gtpu_socket(address_family),
                                       std::move(xdp_sock),
                                       inner_proto,
                                       cookie,
                                       options,
                                       std::move(bpf_state));

    p->encap_worker_index = next_worker_index_round_robin();
    p->decap_worker_index = next_worker_index_round_robin();;

    p->session_leader_pidfd = std::move(session_leader_pidfd);
    delegate->register_session_leader(GtpuTunnelId(id), p->session_leader_pidfd);
    on_failure unregister_session_leader([this, id, &p] () {
        delegate->unregister_session_leader(GtpuTunnelId(id), p->session_leader_pidfd);
    });

    auto key = p->pipe.tunnel().key();
    auto [it, inserted] = session_by_key.insert(std::make_pair(key, p.get()));
    if (!inserted) throw std::system_error(EEXIST, std::generic_category());
    on_failure erase_session([this, it] () { session_by_key.erase(it); });

    register_tunnel(tunnel, p->net_sock_reg);
    on_failure unregister_tunnel([this, &tunnel] () {
        this->unregister_tunnel(tunnel);
    });

    // No need for the matching "on_failure delete_watcher(...)", since
    // net_sock gets closed on failure and auto-removed from epoll.
    //
    // However don't enable yet, as we might be racing with a worker on
    // failure otherwise.
    add_watcher(p->net_sock_watcher().disable());

    add_watcher(p->xdp_sock_watcher());

    // Finally, enable net_sock_watcher (nothrow).
    modify_watcher(p->net_sock_watcher());

    // It's important that we didn't "publish" it earlier.
    // Otherwise register_tunnel() might attempt to double register.
    sessions[id] = std::move(p);

    return { GtpuTunnelId(id), std::move(xdp_bpf_prog) };
}

void GtpdCore::delete_tunnel(GtpuTunnelId id) {
    auto &sess = session_by_id(id);
    delete_watcher(sess.net_sock_watcher());
    delete_watcher(sess.xdp_sock_watcher());
    sync_with_workers(sess);
    session_by_key.erase(sess.pipe.tunnel().key());
    unregister_tunnel(sess.pipe.tunnel());
    delegate->unregister_session_leader(id, sess.session_leader_pidfd);
    sessions[uint32_t(id)].reset();
}

void GtpdCore::modify_tunnel(GtpuTunnelId id,
                             GtpuTunnel new_tunnel, InnerProto new_inner_proto) {

    auto &sess = session_by_id(id);

    ensure_address_family_enabled(new_tunnel.address_family());

    modify_watcher(sess.net_sock_watcher().disable());
    modify_watcher(sess.xdp_sock_watcher().disable());
    on_scope_exit enable_session([this, &sess] () {
        modify_watcher(sess.net_sock_watcher());
        modify_watcher(sess.xdp_sock_watcher());
    });
    sync_with_workers(sess);
    // From now on the session is not accessed concurrently.

    if (sess.pipe.tunnel().key() == new_tunnel.key()) {
        modify_session_socket_and_bpf_maps(sess, new_tunnel);
        sess.pipe.set_tunnel(new_tunnel);
    } else {
        auto [it, inserted]
            = session_by_key.insert(std::make_pair(new_tunnel.key(), &sess));
        if (!inserted) throw std::system_error(EEXIST, std::generic_category());
        on_failure erase_session([this, it] () { session_by_key.erase(it); });

        modify_session_socket_and_bpf_maps(sess, new_tunnel);

        session_by_key.erase(sess.pipe.tunnel().key());
        sess.pipe.set_tunnel(new_tunnel);
        assert(it->first == sess.pipe.tunnel().key());
        // it->first is referring to new_tunnel via
        // string_view pointers, but new_tunnel is going out of scope.
        const_cast<std::u32string_view &>(it->first) = sess.pipe.tunnel().key();
    }

    // Wrapping the code in noexcept lambda, so that the program
    // terminates if it throws.  Rationale: modify_tunnel
    // should either succeed or have no effect.  Implementing
    // rollback for a failure case that doesn't occur is a waste of
    // effort.
    [&sess, new_inner_proto] () noexcept {
        sess.pipe.set_inner_proto(new_inner_proto);
    } ();
}

// Switch between AF_INET and AF_INET6 if necessary and modify BPF maps.
void GtpdCore::modify_session_socket_and_bpf_maps(Session &sess, const GtpuTunnel &new_tunnel) {
    const AF address_family = new_tunnel.address_family();
    if (sess.pipe.tunnel().address_family() == address_family) {
        if (sess.pipe.tunnel().bpf_key() != new_tunnel.bpf_key()) {
            register_tunnel(new_tunnel, sess.net_sock_reg);
            unregister_tunnel(sess.pipe.tunnel());
        }
    } else {
        auto sock = gtpu_socket(address_family);
        add_watcher({
            sock, 0, WatcherInfo{ .type = WatcherType::NET_SOCK, .sess = &sess }
        });

        SocketRegistration sock_reg(sock);
        register_tunnel(new_tunnel, sock_reg);
        unregister_tunnel(sess.pipe.tunnel());

        sess.pipe.set_net_sock(std::move(sock));
        std::swap(sess.net_sock_reg, sock_reg);
        // We rely on socket getting removed from epoll when closed.
    }
}

GtpuTunnelId GtpdCore::next_tunnel(GtpuTunnelId id) {
    for (auto index = uint32_t(id); ++index != sessions.size(); )
        if (sessions[index]) return GtpuTunnelId(index);
    return GtpuTunnelId(0);
}

GtpdCore::Session &GtpdCore::session_by_id(GtpuTunnelId id) {
    auto index = uint32_t(id);
    if (index >= sessions.size() || !sessions[index])
        throw std::system_error(ENOENT, std::generic_category());
    return *sessions[index];
}

const GtpuPipe &GtpdCore::gtpu_pipe(GtpuTunnelId id) {
    return session_by_id(id).pipe;
}

int GtpdCore::halt_code(GtpuTunnelId id) {
    return session_by_id(id).halt.load(std::memory_order_relaxed);
}

void GtpdCore::ensure_address_family_enabled(AF address_family) const {
    if (delegate->tunnel_dispatcher(address_family) == nullptr)
        throw std::system_error(EAFNOSUPPORT, std::generic_category());
}

void GtpdCore::register_tunnel(const GtpuTunnel &tunnel, const SocketRegistration &reg) {
    const AF address_family = tunnel.address_family();
    bool ok = delegate->tunnel_dispatcher(address_family)->register_tunnel(tunnel, reg);
    if (!ok) {
        // Capacity exceeded, create larger dispatcher.
        auto dispatcher = delegate->tunnel_dispatcher(address_family)
            ->create_next_capacity();
        for (const auto &p: sessions) {
            if (p && p->pipe.tunnel().address_family() == address_family)
                dispatcher->register_tunnel(p->pipe.tunnel(), p->net_sock_reg);
        }
        dispatcher->register_tunnel(tunnel, reg);
        delegate->replace_tunnel_dispatcher(address_family, std::move(dispatcher));
    }
}

EpollWatcherInfo<GtpdCore::WatcherInfo> GtpdCore::Session::net_sock_watcher() {
    return {
        pipe.net_sock(), EPOLLIN,
        GtpdCore::WatcherInfo{ WatcherType::NET_SOCK, this }
    };
}

EpollWatcherInfo<GtpdCore::WatcherInfo> GtpdCore::Session::xdp_sock_watcher() {
    return {
        pipe.xdp_sock(), EPOLLIN,
        GtpdCore::WatcherInfo{ WatcherType::XDP_SOCK, this }
    };
}

void GtpdCore::worker_proc(Worker &w) {
    for (;;) {
        std::array<EpollEvent<WatcherInfo>, 16> events;
        // Can't tell whether a signal was delivered, since epoll_pwait
        // doesn't check for pending signals if some events are ready.
        // Doesn't matter as we check for interrupts unconditionally.
        for (const auto &event: w.epoll.pwait(events.data(), events.size(), -1, &sigset_initial)
                                 .inject_event_if_interrupted()) {
            auto info = event.data();
            switch (info.type) {
            case WatcherType::NET_SOCK:
                // .do_decap() returning non-zero halt code indicates
                // that there's something seriously wrong with the
                // session.  It's unsafe to serve it any further as
                // the socket is most likely still ready and we'll
                // busy-loop forever.
                if (int halt = info.sess->pipe.do_decap()) {
                    info.sess->halt.store(halt, std::memory_order_relaxed);
                    w.epoll.modify_watcher_if_exists(info.sess->net_sock_watcher().disable());
                }
                break;
            case WatcherType::XDP_SOCK:
                // See above.
                if (int halt = info.sess->pipe.do_encap()) {
                    info.sess->halt.store(halt, std::memory_order_relaxed);
                    w.epoll.modify_watcher_if_exists(info.sess->xdp_sock_watcher().disable());
                }
                break;
            }

            // Check interrupt once every loop iteration to reduce latency.
            auto interrupt = w.interrupt.load(std::memory_order_acquire);
            if (__builtin_expect(interrupt != Interrupt::NONE, false)) {
                w.interrupt.store(Interrupt::NONE, std::memory_order_release);
                if (interrupt_barrier.counter.fetch_add(-1, std::memory_order_relaxed) == 1) {
                    // counter just dropped to 0 (fetch_add returns the old value)
                    std::unique_lock lock(interrupt_barrier.mutex);
                    interrupt_barrier.cv.notify_one();
                }
                if (interrupt == Interrupt::EXIT) return;

                break; // could've invalidated pending events
            }
        }
    }
}

void GtpdCore::sync_with_workers(const Session &sess) {
    auto is_session_host = [this, &sess] (const Worker &w) {
        return &w == &workers[sess.encap_worker_index]
               || &w == &workers[sess.decap_worker_index];
    };
    interrupt_workers(Interrupt::SYNC, is_session_host);
    std::unique_lock lock(interrupt_barrier.mutex);
    while (interrupt_barrier.counter.load(std::memory_order_relaxed) != 0)
        interrupt_barrier.cv.wait(lock);
}

template<typename Pred>
void GtpdCore::interrupt_workers(Interrupt interrupt, const Pred& pred) {
    int num_active = 0;
    for (const auto &w: workers) {
        if (!pred(w)) continue;
        ++num_active;
    }
    interrupt_barrier.counter.store(num_active, std::memory_order_relaxed);
    for (auto &w: workers) {
        if (!pred(w)) continue;
        w.interrupt.store(interrupt, std::memory_order_release);
    }
    for (auto &w: workers) {
        if (!pred(w)) continue;
        // If workers are active signal might be unnecessary.
        if (interrupt_barrier.counter.load(std::memory_order_relaxed) == 0) return;
        if (auto err = pthread_kill(w.thread.native_handle(), options.interrupt_sig)) {
            fprintf(stderr, "fatal: pthread_kill: %s\n", strerror(err));
            abort();
        }
    }
}

void GtpdCore::stop_workers() {
    auto is_joinable = [] (const Worker &w) { return w.thread.joinable(); };
    interrupt_workers(Interrupt::EXIT, is_joinable);
    for (auto &w: workers) {
        if (w.thread.joinable()) w.thread.join();
    }
}

GtpdCore::GtpdCore(Delegate *delegate, const Options &opts)
        : delegate(delegate), options(opts),
          sessions(2), // [0] never used
          workers(opts.nworkers) {

    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, options.interrupt_sig);
    if (auto err = pthread_sigmask(SIG_BLOCK, &sigset, &sigset_initial)) {
        throw std::system_error(err, std::generic_category(), "pthread_sigmask");
    }

    on_scope_exit restore_sigmask([&] () {
        if (auto err = pthread_sigmask(SIG_SETMASK, &sigset_initial, nullptr)) {
            fprintf(stderr, "fatal: pthread_sigmask: %s\n", strerror(err));
        }
    });

    on_failure stop_workers([this] () { this->stop_workers(); } );

    for (auto &w: workers) {
        // Threads inherit current sigmask, have interrupt_sig blocked.
        w.thread = std::thread([this, &w] () {
            worker_proc(w);
        });
        char tname[16];
        snprintf(tname, sizeof(tname), "gtpd.wk.%d", int(&w - &workers[0]));
        pthread_setname_np(w.thread.native_handle(), tname);
    }
}

GtpdCore::~GtpdCore() {
    stop_workers();
}

Epoll<GtpdCore::WatcherInfo> &GtpdCore::epoll_by_watcher_info(WatcherInfo info) {
    assert(info.type == WatcherType::NET_SOCK || info.type == WatcherType::XDP_SOCK);
    auto worker_index = (
        info.type == WatcherType::NET_SOCK
        ? info.sess->decap_worker_index : info.sess->encap_worker_index
    );
    assert(worker_index >= 0);
    return workers[worker_index].epoll;
}

void GtpdCore::add_watcher(const EpollWatcherInfo<WatcherInfo> &wi) {
    epoll_by_watcher_info(wi.data).add_watcher(wi);
}

void GtpdCore::delete_watcher(const EpollWatcherInfo<WatcherInfo> &wi) {
    epoll_by_watcher_info(wi.data).delete_watcher(wi);
}

void GtpdCore::modify_watcher(const EpollWatcherInfo<WatcherInfo> &wi) {
    epoll_by_watcher_info(wi.data).modify_watcher(wi);
}
