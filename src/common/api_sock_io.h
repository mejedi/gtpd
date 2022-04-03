#pragma once
#include "fd.h"

using Fds = std::array<Fd, 2>;
using FdPtrs = std::array<const Fd *, 2>;

// Convenience wrapper for sendmsg/recvmsg allowing to pass at most N
// file descriptors along with the message.

ssize_t api_sock_send(const Fd &sock, const void *p, size_t sz,
                      FdPtrs fdPtrs, int flags);

std::pair<ssize_t, Fds>
api_sock_recv(const Fd &sock, void *p, size_t sz, int flags);
