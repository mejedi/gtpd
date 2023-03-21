// Minimal library for XDP memory-mapped IO interfaces.
// As XDP socket is shared with gtpd user which could clobber the
// shared memory, we apply extra scrutiny and don't trust the data.
#pragma once
#include "common/fd.h"
#include <atomic>
#include <cassert>
#include <cstddef>
#include <linux/if_xdp.h>
#include <type_traits>

namespace detail {

struct XdpBase {
    XdpBase(XdpBase&) = delete;
    void operator=(XdpBase&) = delete;
    XdpBase() {}
};

} // namespace detail

struct XdpUmem: private detail::XdpBase {

    XdpUmem(const Fd &xdp, uint32_t buf_count, uint32_t buf_size);

    ~XdpUmem();

    // XDP consumes and produces references to buffers/pages via
    // memory-mapped ring buffers.  References are encoded as 64bit
    // offset within UMem area.
    // PageHandle refers to a page as whole.  A canonical page handle is
    // page-size aligned.  The class produces canonical page handles but
    // accepts any page handle.
    // BufHandle refers to a buffer: a memory area starting at a certain
    // offset within a page and spanning until the page end.
    enum class PageHandle: uint64_t {};
    enum class BufHandle: uint64_t {};

    PageHandle page(uint32_t i) {
        assert(i < page_count);
        return PageHandle(i * page_size);
    }

    // Convert a pointer to a buf handle.
    BufHandle buf_handle(void *p) {
        auto *u8p = static_cast<uint8_t *>(p);
        assert(u8p >= base);
        assert(u8p < base + page_size * page_count);
        return BufHandle(u8p - base);
    }

    // Convert a poiner to a page handle.
    PageHandle page_handle(void *p) {
        auto *u8p = static_cast<uint8_t *>(p);
        assert(u8p >= base);
        assert(u8p < base + page_size * page_count);
        return PageHandle((u8p - base) & ~ptrdiff_t(page_size - 1));
    }

    // Convert externally-produced BufHandle to a pointer + max size.
    // Return nullptr on validation error.
    std::pair<void *, uint32_t> open_buf(BufHandle h) {
        auto offset = static_cast<uint64_t>(h);
        if (offset >= page_count * page_size) return {};
        return { base + offset, static_cast<uint32_t>(-offset) & (page_size - 1) };
    }

    // Convert externally-produced BufHandle to a pointer to the data
    // area.  Return nullptr on validation error.
    void *open_buf(PageHandle h) {
        auto offset = static_cast<uint64_t>(h) & ~uint64_t(page_size - 1);
        if (offset >= page_count * page_size) return {};
        return base + offset + xdp_implicit_headroom;
    }

private:
    uint8_t *base;
    uint32_t page_count, page_size;

    // XDP reserves implicit headroom.  Have to account for that when
    // sizing pages in umem.
    static constexpr int xdp_implicit_headroom = 128;
};

namespace detail {

enum class XdpRing {
    Rx = XDP_RX_RING,
    Tx = XDP_TX_RING,
    UmemFill = XDP_UMEM_FILL_RING,
    UmemCompletion = XDP_UMEM_COMPLETION_RING
};

struct XdpRingBase: private XdpBase {
    uint8_t *base;
    uint32_t producer_offset, consumer_offset, desc_offset, mask;
    uint32_t consumer, producer;

    void map(XdpRing ring_type, const Fd &xdp, uint32_t size,
             const xdp_mmap_offsets &mmap_offsets, size_t desc_size);

    void unmap(size_t desc_size);

    std::atomic<uint32_t> *producer_ptr() {
        return reinterpret_cast<std::atomic<uint32_t> *>(base + producer_offset);
    }

    std::atomic<uint32_t> *consumer_ptr() {
        return reinterpret_cast<std::atomic<uint32_t> *>(base + consumer_offset);
    }

    template <typename Desc>
    volatile Desc *desc_ptr() {
        return reinterpret_cast<Desc *>(base + desc_offset);
    }
};

template <XdpRing ring_type, typename Desc>
struct XdpRingConsumer: private XdpRingBase {

    XdpRingConsumer(const Fd &xdp, uint32_t size,
                    const xdp_mmap_offsets &mmap_offsets) {
        map(ring_type, xdp, size, mmap_offsets, sizeof(Desc));
    }

    ~XdpRingConsumer() { unmap(sizeof(Desc)); }

    void reload() {
        producer = producer_ptr()->load(std::memory_order_acquire);
    }

    bool was_clobbered() {
        return consumer != consumer_ptr()->load(std::memory_order_relaxed);
    }

    void advance(uint32_t n) {
        assert(n <= size());
        consumer += n;
        consumer_ptr()->store(consumer, std::memory_order_relaxed);
    }

    uint32_t size() const {
        return (producer - consumer);
    }

    Desc load(uint32_t i) {
        assert(i < size());
        return desc_ptr<Desc>()[mask & (consumer + i)];
    }
};

template <XdpRing ring_type, typename Desc>
struct XdpRingProducer: private XdpRingBase {

    XdpRingProducer(const Fd &xdp, uint32_t size,
                    const xdp_mmap_offsets &mmap_offsets) {
        map(ring_type, xdp, size, mmap_offsets, sizeof(Desc));
    }

    ~XdpRingProducer() { unmap(sizeof(Desc)); }

    void reload() {
        consumer = consumer_ptr()->load(std::memory_order_relaxed);
    }

    void advance(uint32_t n) {
        assert(n <= capacity());
        producer += n;
        producer_ptr()->store(producer, std::memory_order_release);
    }

    uint32_t capacity() const {
        return mask + 1 - (producer - consumer);
    }

    void store(uint32_t i, const Desc &desc) {
        assert(i < capacity());
        desc_ptr<Desc>()[mask & (producer + i)] = desc;
    }
};

} // namespace detail

struct XdpDesc { // xdp_desc
    XdpUmem::BufHandle buf;
    uint32_t len;
    uint32_t options;

    XdpDesc() = default;
    XdpDesc(XdpUmem::BufHandle buf, uint32_t len, uint32_t options):
        buf(buf), len(len), options(options) {}
    XdpDesc(const XdpDesc &) = default;
    XdpDesc(const volatile XdpDesc &other)
        : buf(other.buf), len(other.len), options(other.options) {}
    XdpDesc &operator=(const XdpDesc &) = default;
    void operator=(const XdpDesc &other) volatile {
        buf = other.buf;
        len = other.len;
        options = other.options;
    }
};
static_assert(sizeof(XdpDesc) == sizeof(xdp_desc));
static_assert(std::is_standard_layout_v<XdpDesc>);

using XdpRxRing = detail::XdpRingConsumer<detail::XdpRing::Rx, XdpDesc>;

using XdpTxRing = detail::XdpRingProducer<detail::XdpRing::Tx, XdpDesc>;

using XdpUmemFillRing = detail::XdpRingProducer<detail::XdpRing::UmemFill,
                                                XdpUmem::PageHandle>;

using XdpUmemCompletionRing = detail::XdpRingConsumer<detail::XdpRing::UmemCompletion,
                                                      XdpUmem::PageHandle>;

struct XdpRing {
    static xdp_mmap_offsets mmap_offsets(const Fd &);
};
