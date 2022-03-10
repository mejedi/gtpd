#include "api_sock_io.h"
#include <cassert>
#include <sys/socket.h>
#include <sys/un.h>

ssize_t api_sock_send(const Fd &sock, const void *p, size_t sz,
                      const Fd &fd, int flags) {
    iovec iov = { const_cast<void *>(p), sz };

    msghdr m = {};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;

    uint8_t cmsg_buf[CMSG_SPACE(sizeof(int))] alignas(cmsghdr);
    if (fd) {
        auto *cmsg = reinterpret_cast<cmsghdr *>(cmsg_buf);
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        reinterpret_cast<int *>(CMSG_DATA(cmsg))[0] = fd.get();

        m.msg_control = cmsg_buf;
        m.msg_controllen = CMSG_SPACE(sizeof(int));
    }

   return sendmsg(sock.get(), &m, flags);
}

std::pair<ssize_t, Fd>
api_sock_recv(const Fd &sock, void *p, size_t sz, int flags) {
    iovec iov = { p, sz };

    uint8_t cmsg_buf[CMSG_SPACE(sizeof(int))] alignas(cmsghdr);

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
                assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
                return { rc, Fd(reinterpret_cast<int *>(CMSG_DATA(cmsg))[0]) };
            }
        }
    }

    return { rc, Fd() };
}
