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

template<typename WatcherData>
struct EpollEvent {
    uint32_t events() const { return ev.events; }
    WatcherData data() const { return decode(WatcherData{}, ev.data); }
private:
    epoll_event ev;
};
static_assert(std::is_standard_layout_v<EpollEvent<int>>);
static_assert(sizeof(epoll_event) == sizeof(EpollEvent<int>));

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

    int pwait(Event *events, int maxevents, int timeout, const sigset_t *sigmask = nullptr) {
        return EpollBase::pwait(
            reinterpret_cast<epoll_event *>(events),
            maxevents, timeout, sigmask
        );
    }
};
