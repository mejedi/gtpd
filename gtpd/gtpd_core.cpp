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
    std::thread thread;
};

struct GtpdCore::Watcher {
    int fd;
    uint32_t events;
    uintptr_t data;

    Watcher disable() { return { fd, 0, 0 }; }
};

struct GtpdCore::Session {
    std::atomic_bool enable = true;
    std::atomic_int halt = 0;
    SocketRegistration net_sock_reg;
    GtpuPipe pipe;

    explicit Session(const GtpuTunnel &tun, Fd net_sock, Fd xdp_sock,
                     GtpuPipe::InnerProto inner_proto,
                     GtpuPipe::Cookie cookie,
                     const GtpdCore::Options &opts):
        net_sock_reg(net_sock),
        pipe(tun, std::move(net_sock), std::move(xdp_sock), inner_proto, cookie, opts) {}

    Watcher net_sock_watcher() const;
    Watcher xdp_sock_watcher() const;
};

Fd GtpdCore::create_gtpu_tunnel(const ApiCreateGtpuTunnelMsg &msg,
                                Fd xdp_sock) {
    GtpuTunnel tunnel(msg.tunnel);
    const AF address_family = tunnel.address_family();
    ensure_address_family_enabled(address_family);

    auto p = std::make_unique<Session>(tunnel,
                                       gtpu_socket(address_family),
                                       std::move(xdp_sock),
                                       GtpuPipe::InnerProto(msg.inner_proto),
                                       GtpuPipe::Cookie(msg.cookie),
                                       options);

    Fd xdp_bpf_prog = p->pipe.xdp_bpf_prog();

    auto key = p->pipe.tunnel().key();
    auto [it, inserted] = sessions.insert(std::make_pair(key, decltype(p)()));
    if (!inserted) throw std::system_error(EEXIST, std::generic_category());
    on_failure erase_session([this, it] () { sessions.erase(it); });

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
    update_watcher(p->net_sock_watcher());

    // It's important that we didn't "publish" it earlier.
    // Otherwise register_tunnel() might attempt to double register.
    it->second = std::move(p);

    return xdp_bpf_prog;
}

void GtpdCore::delete_gtpu_tunnel(const ApiDeleteGtpuTunnelMsg &msg) {
    GtpuTunnel tunnel(msg.tunnel);
    auto it = sessions.find(tunnel.key());
    if (it == sessions.end()
        || it->second->pipe.tunnel().local_teid() != tunnel.local_teid()
    ) throw std::system_error(ENOENT, std::generic_category());
    delete_watcher(it->second->net_sock_watcher());
    delete_watcher(it->second->xdp_sock_watcher());
    sync_with_workers();
    auto p = std::move(it->second);
    sessions.erase(it);
    unregister_tunnel(p->pipe.tunnel());
}

void GtpdCore::modify_gtpu_tunnel(const ApiModifyGtpuTunnelMsg &msg) {
    GtpuTunnel tunnel(msg.tunnel);

    auto it = sessions.find(tunnel.key());
    if (it == sessions.end()
        || it->second->pipe.tunnel().local_teid() != tunnel.local_teid()
    ) throw std::system_error(ENOENT, std::generic_category());
    auto *sess = it->second.get();

    sess->enable.store(false, std::memory_order_relaxed);
    on_scope_exit enable_session([this, sess] () {
        sess->enable.store(true, std::memory_order_release);
        update_watcher(sess->net_sock_watcher());
        update_watcher(sess->xdp_sock_watcher());
    });
    sync_with_workers();
    // From now on the session is not accessed concurrently (except for enable field).
    // Unlike delete_session, we don't EPOLL_CTL_DEL as we might
    // be unable to add it back (EPOLL_CTL_ADD allocates memory).

    if (msg.flags & API_MODIFY_GTPU_TUNNEL_TUNNEL_FLAG) {
        GtpuTunnel new_tunnel(msg.new_tunnel);
        ensure_address_family_enabled(new_tunnel.address_family());

        if (tunnel.key() == new_tunnel.key()) {
            modify_session_socket_and_bpf_maps(sess, new_tunnel);
        } else {
            auto [new_it, inserted]
                = sessions.insert(std::make_pair(new_tunnel.key(), std::unique_ptr<Session>()));
            if (!inserted) throw std::system_error(EEXIST, std::generic_category());
            on_failure erase_session([this, new_it] () { sessions.erase(new_it); });

            modify_session_socket_and_bpf_maps(sess, new_tunnel);

            new_it->second = std::move(it->second);
            sessions.erase(it);
            it = new_it;
        }

        sess->pipe.set_tunnel(new_tunnel);
        assert(it->first == sess->pipe.tunnel().key());
        // it->first might be referring to new_tunnel via
        // string_view pointers, but new_tunnel is going out of scope.
        const_cast<std::u32string_view &>(it->first) = sess->pipe.tunnel().key();
    }

    if (msg.flags & API_MODIFY_GTPU_TUNNEL_INNER_PROTO_FLAG) {
        // Wrapping the code in noexcept lambda, so that the program
        // terminates if it throws.  Rationale: modify_gtpu_tunnel
        // should either succeed or have no effect.  Implementing
        // rollback for a failure case that doesn't occur is a waste of
        // effort.
        [sess, &msg] () noexcept {
            sess->pipe.set_inner_proto(GtpuPipe::InnerProto(msg.new_inner_proto));
        } ();
    }
}

// Switch between AF_INET and AF_INET6 if necessary and modify BPF maps.
void GtpdCore::modify_session_socket_and_bpf_maps(Session* sess, const GtpuTunnel &new_tunnel) {
    const AF address_family = new_tunnel.address_family();
    if (sess->pipe.tunnel().address_family() == address_family) {
        if (sess->pipe.tunnel().bpf_key() != new_tunnel.bpf_key()) {
            register_tunnel(new_tunnel, sess->net_sock_reg);
            unregister_tunnel(sess->pipe.tunnel());
        }
    } else {
        auto sock = gtpu_socket(address_family);
        add_watcher({ sock.get(), 0, 0 });

        SocketRegistration sock_reg(sock);
        register_tunnel(new_tunnel, sock_reg);
        unregister_tunnel(sess->pipe.tunnel());

        sess->pipe.set_net_sock(std::move(sock));
        std::swap(sess->net_sock_reg, sock_reg);
        // We rely on socket getting removed from epoll when closed.
    }
}

void GtpdCore::ensure_address_family_enabled(AF address_family) const {
    if (delegate->tunnel_dispatcher(address_family) == nullptr)
        throw std::system_error(EAFNOSUPPORT, std::generic_category());
}

std::optional<ApiGtpuTunnelListItemMsg>
GtpdCore::list_gtpu_tunnels_next(const ApiListGtpuTunnelsMsg &,
                                 const ApiGtpuTunnel *cur)
{
    auto it = cur ? sessions.upper_bound(GtpuTunnel(*cur).key())
              : sessions.begin();
    if (it == sessions.end()) return {};
    ApiGtpuTunnelListItemMsg res = {};
    res.length = sizeof(res);
    res.code = API_GTPU_TUNNEL_LIST_ITEM_CODE;
    const auto& sess = it->second;
    res.tunnel = sess->pipe.tunnel().api_gtpu_tunnel();
    res.inner_proto = uint32_t(sess->pipe.inner_proto());
    res.halt = sess->halt.load(std::memory_order_relaxed);
    res.cookie = uint32_t(sess->pipe.cookie());
    res.encap_ok = sess->pipe.encap_ok();
    res.encap_drop_rx = sess->pipe.encap_drop_rx();
    res.encap_drop_tx = sess->pipe.encap_drop_tx();
    res.decap_ok = sess->pipe.decap_ok();
    res.decap_drop_rx = sess->pipe.decap_drop_rx();
    res.decap_drop_tx = sess->pipe.decap_drop_tx();
    res.decap_bad = sess->pipe.decap_bad();
    res.decap_trunc = sess->pipe.decap_trunc();
    return res;
}

void GtpdCore::register_tunnel(const GtpuTunnel &tunnel, const SocketRegistration &reg) {
    const AF address_family = tunnel.address_family();
    bool ok = delegate->tunnel_dispatcher(address_family)->register_tunnel(tunnel, reg);
    if (!ok) {
        // Capacity exceeded, create larger dispatcher.
        auto dispatcher = delegate->tunnel_dispatcher(address_family)
            ->create_next_capacity();
        for (const auto &[_, p]: sessions) {
            // p could be nullptr if create_ / modify_session is in progress
            if (p && p->pipe.tunnel().address_family() == address_family)
                dispatcher->register_tunnel(p->pipe.tunnel(), p->net_sock_reg);
        }
        dispatcher->register_tunnel(tunnel, reg);
        delegate->replace_tunnel_dispatcher(address_family, std::move(dispatcher));
    }
}

int GtpdCore::watcher_epoll_ctl(int op, GtpdCore::Watcher w) {
    struct epoll_event evt = {};
    evt.events = w.events;
    evt.data.u64 = w.data;
    return epoll_ctl(epoll.get(), op, w.fd, &evt);
}

void GtpdCore::add_watcher(Watcher w) {
    if (watcher_epoll_ctl(EPOLL_CTL_ADD, w) != 0)
        throw std::system_error(errno, std::generic_category(), "epoll_ctl(ADD)");
}

void GtpdCore::delete_watcher(Watcher w) noexcept {
    if (watcher_epoll_ctl(EPOLL_CTL_DEL, w) != 0) {
        fprintf(stderr, "fatal: epoll_ctl(DEL): %s\n", strerror(errno));
        abort();
    }
}

void GtpdCore::update_watcher(Watcher w) noexcept {
    // Can fail with ENOENT if main removes concurrently.
    if (watcher_epoll_ctl(EPOLL_CTL_MOD, w) != 0 && errno != ENOENT) {
        fprintf(stderr, "fatal: epoll_ctl(MOD): %s\n", strerror(errno));
        abort();
    }
}

static constexpr int NET_SOCK_WATCHER = 1;
static constexpr int XDP_SOCK_WATCHER = 2;

template<typename T>
std::pair<T *, int> decode_watcher_data(uintptr_t data) {
    constexpr uintptr_t M = 3;
    return { reinterpret_cast<T *>(data & ~M), static_cast<int>(data & M) };
}

GtpdCore::Watcher GtpdCore::Session::net_sock_watcher() const {
    return { pipe.net_sock().get(), EPOLLIN | EPOLLONESHOT,
             reinterpret_cast<uintptr_t>(this) | NET_SOCK_WATCHER };
}

GtpdCore::Watcher GtpdCore::Session::xdp_sock_watcher() const {
    return { pipe.xdp_sock().get(), EPOLLIN | EPOLLONESHOT,
             reinterpret_cast<uintptr_t>(this) | XDP_SOCK_WATCHER };
}

void GtpdCore::worker_proc(Worker &w) {
    for (;;) {
        epoll_event evt;
        // Can't tell whether a signal was delivered, since epoll_pwait
        // doesn't check for pending signals if some events are ready.
        // Doesn't matter as we check for interrupts unconditionally.
        if (epoll_pwait(epoll.get(), &evt, 1, -1, &sigset_initial) == 1) {
            auto [sess, type] = decode_watcher_data<Session>(evt.data.u64);
            if (__builtin_expect(sess->enable.load(std::memory_order_acquire), true)) {
                switch (type) {
                case NET_SOCK_WATCHER:
                    // .do_decap() returning non-zero halt code indicates
                    // that there's something seriously wrong with the
                    // session.  It's unsafe to serve it any further as
                    // the socket is most likely still ready and we'll
                    // busy-loop forever.
                    if (int halt = sess->pipe.do_decap()) {
                        sess->halt.store(halt, std::memory_order_relaxed);
                    } else {
                        update_watcher(sess->net_sock_watcher());
                    }
                    break;
                case XDP_SOCK_WATCHER:
                    // See above.
                    if (int halt = sess->pipe.do_encap()) {
                        sess->halt.store(halt, std::memory_order_relaxed);
                    } else {
                        update_watcher(sess->xdp_sock_watcher());
                    }
                    break;
                }
            }
        } else if (errno != EINTR) {
            fprintf(stderr, "fatal: epoll_pwait: %s\n", strerror(errno));
            abort();
        }
        auto interrupt = w.interrupt.load(std::memory_order_acquire);
        if (__builtin_expect(interrupt != Interrupt::NONE, false)) {
            if (interrupt_barrier.counter.fetch_add(-1, std::memory_order_relaxed) == 1) {
                // counter just dropped to 0 (fetch_add returns the old value)
                std::unique_lock lock(interrupt_barrier.mutex);
                interrupt_barrier.cv.notify_one();
            }
            w.interrupt.store(Interrupt::NONE, std::memory_order_release);
            if (interrupt == Interrupt::EXIT) return;
        }
    }
}

void GtpdCore::sync_with_workers() {
    interrupt_workers(Interrupt::SYNC);
    std::unique_lock lock(interrupt_barrier.mutex);
    while (interrupt_barrier.counter.load(std::memory_order_relaxed) != 0)
        interrupt_barrier.cv.wait(lock);
}

void GtpdCore::interrupt_workers(Interrupt interrupt) {
    int num_active = 0;
    for (const auto &w: workers) {
        if (w.thread.joinable()) ++num_active;
    }
    interrupt_barrier.counter.store(num_active, std::memory_order_relaxed);
    for (auto &w: workers) {
        if (!w.thread.joinable()) continue;
        w.interrupt.store(interrupt, std::memory_order_release);
    }
    for (auto &w: workers) {
        if (!w.thread.joinable()) continue;
        // If workers are active signal might be unnecessary.
        if (interrupt_barrier.counter.load(std::memory_order_relaxed) == 0) return;
        if (auto err = pthread_kill(w.thread.native_handle(), options.interrupt_sig)) {
            fprintf(stderr, "fatal: pthread_kill: %s\n", strerror(err));
            abort();
        }
    }
}

void GtpdCore::stop_workers() {
    interrupt_workers(Interrupt::EXIT);
    for (auto &w: workers) {
        if (w.thread.joinable()) w.thread.join();
    }
}

GtpdCore::GtpdCore(Delegate *delegate, const Options &opts)
        : delegate(delegate), options(opts),
          epoll(epoll_create1(EPOLL_CLOEXEC)),
          workers(opts.nworkers) {
    if (!epoll)
        throw std::system_error(errno, std::generic_category(), "epoll_create");

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
    }
}

GtpdCore::~GtpdCore() {
    stop_workers();
}