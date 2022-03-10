#pragma once
#include "fd.h"

// Convenience wrapper for sendmsg/recvmsg allowing to pass at most 1
// file descriptor along with the message.

ssize_t api_sock_send(const Fd &sock, const void *p, size_t sz,
                      const Fd &fd, int flags);

std::pair<ssize_t, Fd>
api_sock_recv(const Fd &sock, void *p, size_t sz, int flags);
