#pragma once
#include <algorithm>
#include <atomic>
#include <new>
#include <cstdlib>

namespace detail {
extern const size_t cache_line_size;
}

// Derive from CacheLineAligned to ensure that dynamically-allocated
// instances are cache line-aligned, e.g:
//
// class Foobar: public CacheLineAligned<Foobar> { ... };
//
// The curiously-recurring template pattern is used to
// (1) respect class' own alignment, and (2) ensure that unrelated
// classes deriving from CacheLineALigned don't share a common base
// class.
template<typename T>
struct CacheLineAligned {
    static void* operator new(std::size_t size) {
        return alloc(size);
    }

    static void operator delete(void* p) noexcept { free(p); }

protected:
    static void* alloc(std::size_t size) {
        // gcc 9 lacks std::hardware_destructive_interference_size
        const auto align = std::max(alignof(T), detail::cache_line_size);
        void *p;
        if (posix_memalign(&p, align, size) != 0) {
            throw std::bad_alloc();
        }
        return p;
    }
};
