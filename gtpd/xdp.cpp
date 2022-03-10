#include "xdp.h"
#include <cassert>
#include <system_error>
#include <sys/mman.h>
#include <sys/socket.h>


XdpUmem::XdpUmem(const Fd &xdp, uint32_t buf_count, uint32_t buf_size) {
    page_count = buf_count;
    if (buf_size <= 2048 - xdp_implicit_headroom) {
        page_size = 2048;
    } else if (buf_size <= 4096 - xdp_implicit_headroom) {
        page_size = 4096;
    } else {
        throw std::system_error(
            EINVAL, std::generic_category(), "XDP buffer size too big"
        );
    }

    auto *p = mmap(0, page_size * page_count, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p == MAP_FAILED) {
        throw std::system_error(errno, std::generic_category(), "Map XDP umem");
    }
    base = static_cast<uint8_t *>(p);

    xdp_umem_reg reg = {};
    reg.chunk_size = page_size;
    reg.len = page_size * page_count;
    reg.addr = reinterpret_cast<uint64_t>(p);

    if (setsockopt(xdp.get(), SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)) != 0) {
        int err = errno;
        munmap(p, page_size * page_count);
        throw std::system_error(err, std::generic_category(), "Register XDP umem");
    }
}

XdpUmem::~XdpUmem() {
    munmap(base, page_size * page_count);
}

namespace detail {

void XdpRingBase::map(XdpRing ring_type, const Fd &xdp, uint32_t size,
                      const xdp_mmap_offsets &mmap_offsets,
                      size_t desc_size) {

    off_t pgoff;
    const xdp_ring_offset *ro;

    switch (ring_type) {
    case XdpRing::Rx:
        pgoff = XDP_PGOFF_RX_RING;
        ro = &mmap_offsets.rx;
        break;
    case XdpRing::Tx:
        pgoff = XDP_PGOFF_TX_RING;
        ro = &mmap_offsets.tx;
        break;
    case XdpRing::UmemFill:
        pgoff = XDP_UMEM_PGOFF_FILL_RING;
        ro = &mmap_offsets.fr;
        break;
    case XdpRing::UmemCompletion:
        pgoff = XDP_UMEM_PGOFF_COMPLETION_RING;
        ro = &mmap_offsets.cr;
        break;
    default:
        assert(0);
        __builtin_unreachable();
    }

    producer_offset = ro->producer;
    consumer_offset = ro->consumer;
    desc_offset = ro->desc;
    consumer = 0;
    producer = 0;

    // round up to the power of 2
    size = uint32_t(1) << (32 - __builtin_clz(
        std::max(std::min(size, uint32_t(1) << 31), uint32_t(2)) - 1
    ));
    mask = size - 1;

    if (setsockopt(xdp.get(), SOL_XDP, int(ring_type), &size, sizeof(size)) != 0) {
        throw std::system_error(
            errno, std::generic_category(),
            "setsockopt(XDP_RX_RING / XDP_TX_RING / ...)"
        );
    }

    auto *p = mmap(nullptr, desc_offset + size * desc_size,
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                   xdp.get(), pgoff);
    if (p == MAP_FAILED) {
        throw std::system_error(errno, std::generic_category(), "mmap(XDP ring)");
    }

    base = static_cast<uint8_t *>(p);
}

void XdpRingBase::unmap(size_t desc_size) {
    if (munmap(base, desc_offset + (mask + 1) * desc_size) != 0) {
        throw std::system_error(errno, std::generic_category(), "munmap(XDP ring)");
    }
}

} // namespace detail

xdp_mmap_offsets XdpRing::mmap_offsets(const Fd &xdp) {
    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);
    if (getsockopt(xdp.get(), SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) != 0) {
        throw std::system_error(
            errno, std::generic_category(), "getsockopt(XDP_MMAP_OFFSETS)"
        );
    }
    return off;
}
