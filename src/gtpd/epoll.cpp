#include "epoll.h"
#include <system_error>

EpollBase::EpollBase(): epoll_fd(epoll_create1(EPOLL_CLOEXEC)) {
    if (!epoll_fd)
        throw std::system_error(errno, std::generic_category(), "epoll_create1");
}

void EpollBase::add_watcher(int fd, epoll_event ev) {
    if (epoll_ctl(epoll_fd.get(), EPOLL_CTL_ADD, fd, &ev) != 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_ctl(ADD)");
    }
}

void EpollBase::delete_watcher(int fd, epoll_event ev) {
    if (epoll_ctl(epoll_fd.get(), EPOLL_CTL_DEL, fd, &ev) != 0) {
        fprintf(stderr, "fatal: epoll_ctl(DEL): %s\n", strerror(errno));
        abort();
    }
}

void EpollBase::modify_watcher(int fd, epoll_event ev) {
    if (epoll_ctl(epoll_fd.get(), EPOLL_CTL_MOD, fd, &ev) != 0) {
        fprintf(stderr, "fatal: epoll_ctl(MOD): %s\n", strerror(errno));
        abort();
    }
}

void EpollBase::modify_watcher_if_exists(int fd, epoll_event ev) {
    if (epoll_ctl(epoll_fd.get(), EPOLL_CTL_MOD, fd, &ev) != 0
        && errno != ENOENT
    ) {
        fprintf(stderr, "fatal: epoll_ctl(MOD): %s\n", strerror(errno));
        abort();
    }
}

int EpollBase::pwait(epoll_event *events, int maxevents, int timeout,
                     const sigset_t *sigmask) {
    int rc = epoll_pwait(epoll_fd.get(), events, maxevents, timeout, sigmask);
    if (rc == -1) {
        if (errno != EINTR) {
            fprintf(stderr, "fatal: epoll_pwait: %s\n", strerror(errno));
            abort();
        }
        rc = 0;
    }
    return rc;
}
