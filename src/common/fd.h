#pragma once
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cerrno>

// File descriptor handle with the semantics similar to std::unique_ptr.
class Fd {
    int fd_ = -1;
public:
    Fd() {}
    explicit Fd(int fd): fd_(fd) {}
    ~Fd() {
        if (fd_ != -1 && close(fd_)) {
            fprintf(stderr, "warn: close(%d): %s\n", fd_, strerror(errno));
        }
    }
    Fd(Fd&& other) noexcept { std::swap(fd_, other.fd_); }
    const Fd& operator=(Fd&& other) noexcept {
        std::swap(fd_, other.fd_);
        return *this;
    }
    operator bool() const { return fd_ != -1; }
    int get() const { return fd_; }
};
