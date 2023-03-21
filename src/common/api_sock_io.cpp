#include "api_sock_io.h"
#include <cassert>
#include <cstdint>
#include <sys/socket.h>
#include <sys/un.h>

ssize_t api_sock_send(const Fd &sock, const void *p, size_t sz,
                      FdPtrs fdPtrs, int flags) {
    iovec iov = { const_cast<void *>(p), sz };

    msghdr m = {};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;

    uint8_t cmsg_buf[
        CMSG_SPACE(sizeof(int) * std::tuple_size<FdPtrs>::value)
    ] alignas(cmsghdr);
    auto *cmsg = reinterpret_cast<cmsghdr *>(cmsg_buf);
    int n = 0;

    for (auto p: fdPtrs) {
        if (p && *p) reinterpret_cast<int *>(CMSG_DATA(cmsg))[n++] = p->get();
    }

    if (n) {
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        m.msg_control = cmsg_buf;
        m.msg_controllen = CMSG_SPACE(sizeof(int) * n);
    }

    return sendmsg(sock.get(), &m, flags);
}

std::pair<ssize_t, Fds>
api_sock_recv(const Fd &sock, void *p, size_t sz, int flags) {
    iovec iov = { p, sz };

    uint8_t cmsg_buf[
        CMSG_SPACE(sizeof(int) * std::tuple_size<Fds>::value)
    ] alignas(cmsghdr);

    msghdr m = {};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = cmsg_buf;
    m.msg_controllen = sizeof(cmsg_buf);

    ssize_t rc = recvmsg(sock.get(), &m, flags);

    if (rc > 0) {
        if (auto *cmsg = CMSG_FIRSTHDR(&m)) {
            if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type == SCM_RIGHTS
            ) {
                Fds fds;
                for (unsigned i = 0, len = sizeof(int);
                    cmsg->cmsg_len >= CMSG_LEN(len);
                    ++i, len += sizeof(int)
                ) {
                    fds[i] = Fd(reinterpret_cast<int*>(CMSG_DATA(cmsg))[i]);
                }
                return { rc, std::move(fds) };
            }
        }
    }

    return { rc, Fds() };
}
