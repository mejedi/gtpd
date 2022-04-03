#pragma once
#include <sys/epoll.h>
#include <type_traits>
#include "common/fd.h"

struct EpollBase {
    EpollBase();
    void add_watcher(int fd, epoll_event);
    void delete_watcher(int fd, epoll_event);
    void modify_watcher(int fd, epoll_event);
    void modify_watcher_if_exists(int fd, epoll_event);
    int pwait(epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask);
private:
    Fd epoll_fd;
};

// EpollWatcherInfo: a triple defining epoll watcher.  Consists of
//  - file descriptor to monitor (fd),
//  - mode (events, e.g. EPOLLIN),
//  - user data, delivered as is in epoll events (data).
//
// Internally, epoll allocates 64 bits to encode user data.  We are free
// to use arbitrary type (WatcherData), provided that free-standing
// encode() and decode() functions are available to convert to
// epoll_data and back.
template<typename WatcherData>
struct EpollWatcherInfo {
    int fd;
    uint32_t events;
    WatcherData data;

    EpollWatcherInfo(const Fd& fd, uint32_t events = 0, WatcherData data = {})
        : fd(fd.get()), events(events), data(data) {}

    EpollWatcherInfo disable() const { return { fd, data }; }

private:
    EpollWatcherInfo(int fd, WatcherData data): fd(fd), events(0), data(data) {}
};

// EpollEvent: event as delivered by epoll. Consists of
//  - readiness bits (events, e.g. EPOLLIN),
//  - user data (data).
//
// We support arbitrary type for user data (WatcherData).  See
// EpollWatcherInfo for details.
template<typename WatcherData>
struct EpollEvent {
    uint32_t events() const { return ev.events; }
    WatcherData data() const { return decode(WatcherData{}, ev.data); }
private:
    epoll_event ev;
};
static_assert(std::is_standard_layout_v<EpollEvent<int>>);
static_assert(sizeof(epoll_event) == sizeof(EpollEvent<int>));

// Under typical use, epoll delivers a batch of events at once.  It is
// posible to invalidate later events while handling earlier events in a
// batch.  Use clear_pending_events to scrub events that shouldn't be
// considered anymore, identified by WatcherData.
//
// As the function doesn't move events around, it doesn't need to know
// the processing loop's current position in the batch.
template<typename Iter, typename WatcherData>
void clear_pending_events(Iter begin, Iter end, WatcherData data,
                          WatcherData replacement = WatcherData()) {
    for (auto it = begin; it != end; ++it) {
        auto &ev = *reinterpret_cast<epoll_event *>(&*it);
        if (ev.data.u64 == encode(data).u64)
            ev.data = encode(replacement);
    }
}

template<typename WatcherData>
struct Epoll: private EpollBase {
    using WatcherInfo = EpollWatcherInfo<WatcherData>;
    using Event = EpollEvent<WatcherData>;

    void add_watcher(const WatcherInfo &wi) {
        EpollBase::add_watcher(wi.fd, epoll_event{ wi.events, encode(wi.data) });
    }

    void delete_watcher(const WatcherInfo &wi) {
        EpollBase::delete_watcher(wi.fd, epoll_event{ wi.events, encode(wi.data) });
    }

    void modify_watcher(const WatcherInfo &wi) {
        EpollBase::modify_watcher(wi.fd, epoll_event{ wi.events, encode(wi.data) });
    }

    void modify_watcher_if_exists(const WatcherInfo &wi) {
        EpollBase::modify_watcher_if_exists(wi.fd, epoll_event{ wi.events, encode(wi.data) });
    }

    // support for range loop over pwait() result
    struct EventRange {
        Event *events;
        int rc;

        const Event *begin() const { return events; }
        const Event *end() const { return events + rc; }
        EventRange inject_event_if_interrupted(WatcherData data = WatcherData()) {
            if (__builtin_expect(!rc, false)) {
                reinterpret_cast<epoll_event *>(events)->data = encode(data);
                return { events, 1 };
            }
            return *this;
        }
    };

    EventRange pwait(Event *events, int maxevents, int timeout, const sigset_t *sigmask = nullptr) {
        int rc = EpollBase::pwait(
            reinterpret_cast<epoll_event *>(events),
            maxevents, timeout, sigmask
        );
        return { events, rc };
    }
};
