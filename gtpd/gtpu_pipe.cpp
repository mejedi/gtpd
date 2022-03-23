#include "gtpu_pipe.h"
#include "bpf.h"
#include "bpf_insn.h"
#include "gtpu.h"
#include <linux/if_ether.h>
#include <system_error>
#include <sys/mman.h>

// uprobes
#pragma GCC visibility push(default)
extern "C" {

__attribute__((noinline, noclone)) void
gtpd_encap_update(GtpuPipe::Cookie cookie, uint64_t encap_ok,
                  uint64_t encap_drop_rx, uint64_t encap_drop_tx) {
    asm volatile ("");
}

__attribute__((noinline, noclone)) void
gtpd_decap_update(GtpuPipe::Cookie cookie, uint64_t decap_ok,
                  uint64_t decap_drop_rx, uint64_t decap_drop_tx,
                  uint64_t decap_bad, uint64_t decap_trunc) {
    asm volatile ("");
}

}
#pragma GCC visibility pop

// Derive from CacheLineAligned to ensure that dynamically-allocated
// instances are cache line-aligned.
struct CacheLineAligned {
    static void* operator new(std::size_t size) {
        void *p;
        if (posix_memalign(&p, cache_line_size, size) != 0) {
            throw std::bad_alloc();
        }
        return p;
    }

    static void operator delete(void* p) noexcept { free(p); }

    static const size_t cache_line_size;
};
const size_t CacheLineAligned::cache_line_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

struct BpfStateData {
    volatile uint16_t inner_proto;
    volatile uint64_t rx;
};

GtpuPipe::BpfState::BpfState(): fd(bpf_create_map(
    BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(BpfStateData), 1,
    BPF_F_MMAPABLE
)) {}

// EncapState hosts bits related to encapsulation (XDP->NET).
// As encap and decap could happen concurrently, ensure that EncapState
// is separated from the rest of GtpuPipe bits in a cache line-aligned
// allocation to avoid false sharing.
// Pre-allocate and init objects used by sendmmsg() call (NET output).
struct GtpuPipe::EncapState: CacheLineAligned {
    XdpRxRing rx;
    XdpUmemFillRing umem_fill;
    std::vector<mmsghdr> mmsg; // batch_size
    std::vector<iovec> iov;  // 2x batch size
    std::vector<GtpuHeader> gtpu; // batch_size
    GtpuTunnel::MsgMetaStorage msg_meta;

    BpfStateData *bpf_state = nullptr;

    // Counters
    volatile uint64_t ok = 0, drop_rx = 0, drop_tx = 0;

    EncapState(const Fd &xdp,
               const Options &opts,
               const xdp_mmap_offsets &mmap_offsets,
               BpfState bpf_state)
        : rx(xdp, opts.xdp_pool_size / 2, mmap_offsets),
          umem_fill(xdp, opts.xdp_pool_size, mmap_offsets),
      // Why UmemFill (and Tx) ring is 2x the size?
      // Kernel moves frames from UmemFill to Rx, and from Tx to
      // UmemCompletion.  The pipe moves frames back from Rx to
      // UmemFill, and from UmemCompletion to Tx.  Imagine there's N
      // buffers circulating, and both source and destination rings are
      // exactly of size N.
      // Kernel updates dest ring, e.g. Rx, first. The pipe tries to put
      // frames back to UmemFill, but there might be not enough free
      // space left in UmemFill as the kernel haven't updated it yet.
      // (The amount of entries in source and destination rings could
      // briefly exceed the number of frames in circulation.)
          mmsg(opts.batch_size), iov(2 * opts.batch_size),
          gtpu(opts.batch_size) {

        for (int i = 0; i < opts.batch_size; ++i) {
            mmsg[i].msg_hdr.msg_iov = &iov[i * 2];
            mmsg[i].msg_hdr.msg_iovlen = 2;
            iov[i * 2].iov_base = &gtpu[i];
            iov[i * 2].iov_len = GTPU_FIXED_SIZE;
            gtpu[i].ver_flags = GTPU_V1_VER | GTPU_PT_BIT;
            gtpu[i].type = GTPU_TYPE_GPDU;
        }

        auto *p = mmap(
            nullptr, sizeof(BpfStateData),
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, bpf_state.fd.get(), 0
        );
        if (p == MAP_FAILED) {
            throw std::system_error(errno, std::generic_category(), "mmap bpf map");
        }

        this->bpf_state = static_cast<BpfStateData *>(p);
    }

    ~EncapState() {
        munmap(bpf_state, sizeof(BpfStateData));
    }
};

// DecapState hosts bits related to decapsulation (NET->XDP).
// Pre-allocate and init objects used by recvmmsg() call (NET input).
// Each call to recvmmsg() consumes up to batch_size datagrams using
// mmsg[mmsg_offset: mmsg_offset + batch_size].  Normally mmsg_offset is
// zero. If insufficient buffers are available, the offset could be
// larger, up to the batch_size.
// The number of frames in mmsg is 2x the batch size.  The second half
// uses a dummy buffer.  Recieving into a dummy buffer discards input.
struct GtpuPipe::DecapState: CacheLineAligned {
    XdpTxRing tx;
    XdpUmemCompletionRing umem_completion;
    uint32_t mmsg_offset;
    uint32_t n_pages_free;
    std::vector<mmsghdr> mmsg; // 2x batch_size
    std::vector<iovec> iov; // batch_size
    iovec dummy_iov;
    uint8_t dummy_buf[1];

    uint32_t rxq_overflow_last = 0;
    uint8_t cmsg_buf[CMSG_SPACE(sizeof(int))] alignas(cmsghdr);

    // Counters
    volatile uint64_t ok = 0, drop_rx = 0, drop_tx = 0;
    volatile uint64_t bad = 0, trunc = 0;

    DecapState(const Fd &xdp,
               const Options &opts,
               const xdp_mmap_offsets &mmap_offsets)
        : tx(xdp, opts.xdp_pool_size, mmap_offsets),
          umem_completion(xdp, opts.xdp_pool_size / 2, mmap_offsets),
      // Why Tx ring is 2x the size?  See notes in EncapState.
          mmsg_offset(opts.batch_size),
          mmsg(2 * opts.batch_size), iov(opts.batch_size) {

        dummy_iov.iov_base = dummy_buf;
        dummy_iov.iov_len = sizeof(dummy_buf);

        for (int i = 0; i < opts.batch_size; ++i) {
            mmsg[i].msg_hdr.msg_iov = &iov[i];
            mmsg[i].msg_hdr.msg_iovlen = 1;
            mmsg[i].msg_hdr.msg_control = cmsg_buf;
            mmsg[i].msg_hdr.msg_controllen = sizeof(cmsg_buf);
            iov[i].iov_len = opts.encap_mtu;

            mmsg[i + opts.batch_size].msg_hdr.msg_iov = &dummy_iov;
            mmsg[i + opts.batch_size].msg_hdr.msg_iovlen = 1;
            mmsg[i + opts.batch_size].msg_hdr.msg_control = cmsg_buf;
            mmsg[i + opts.batch_size].msg_hdr.msg_controllen = sizeof(cmsg_buf);
        }
    }

    // The number of ingress packets dropped by the socket since last
    // receive.  Absolute number of drops delivered via
    // SOL_SOCKET/SO_RQ_OVFL ancillary message.
    uint32_t rxq_overflow_delta(int index) {
        if (auto *cmsg = CMSG_FIRSTHDR(&mmsg[index].msg_hdr)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL) {
                assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
                int cur = *reinterpret_cast<int *>(CMSG_DATA(cmsg));
                int delta = cur - rxq_overflow_last;
                rxq_overflow_last = cur;
                return delta;
            }
        }
        return 0;
    }
};

GtpuPipe::GtpuPipe(const GtpuTunnel &tunnel, Fd net_sock, Fd xdp_sock,
                   InnerProto inner_proto, Cookie cookie,
                   const Options &opts,
                   BpfState bpf_state)
    : GtpuPipe(tunnel, net_sock, xdp_sock, inner_proto, cookie, opts,
               XdpRing::mmap_offsets(xdp_sock),
               std::move(bpf_state)) {}

GtpuPipe::GtpuPipe(const GtpuTunnel &tunnel, Fd &net_sock, Fd &xdp_sock,
                   InnerProto inner_proto, Cookie cookie,
                   const Options &opts,
                   xdp_mmap_offsets mmap_offsets,
                   BpfState bpf_state)
    : tunnel_(tunnel),
      xdp_sock_(std::move(xdp_sock)),
      inner_proto_(inner_proto),
      cookie_(cookie),
      batch_size(opts.batch_size),
      xdp_umem(xdp_sock_, opts.xdp_pool_size, opts.encap_mtu),
      encap_state(std::make_unique<EncapState>(xdp_sock_, opts, mmap_offsets,
                  std::move(bpf_state))),
      decap_state(std::make_unique<DecapState>(xdp_sock_, opts, mmap_offsets)) {

    // Reserve half a pool for Decap and the rest for Encap (e.g. 10 and 11
    // for a pool of 21).
    auto decap_quota = opts.xdp_pool_size / 2;
    auto encap_quota = opts.xdp_pool_size - decap_quota;

    decap_state->n_pages_free = decap_quota;

    // Init fill ring (buffers to be consumed by Rx).
    encap_state->umem_fill.reload();
    for (int i = 0; i < encap_quota; ++i) {
        // Note: first decap_quota pages are for Decap, skip them.
        encap_state->umem_fill.store(i, xdp_umem.page(decap_quota + i));
    }
    encap_state->umem_fill.advance(encap_quota);

    on_tunnel_updated();
    on_inner_proto_updated();
    set_net_sock(std::move(net_sock));
}

GtpuPipe::~GtpuPipe() {}

void GtpuPipe::set_net_sock(Fd net_sock) {
    // Ask to deliver the number of Rx drops via SOL_SOCKET/SO_RXQ_OVFL
    // ancillary message.
    int t = 1;
    if (setsockopt(net_sock.get(), SOL_SOCKET, SO_RXQ_OVFL, &t, sizeof(t)) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "setsockopt(SO_RXQ_OVFL)");
    }

    net_sock_ = std::move(net_sock);
    decap_state->rxq_overflow_last = 0;
}

// .do_encap() returning non-zero halt code indicates that there's
// something seriously wrong with the session.  It's unsafe to serve it
// any further as the socket is most likely still ready and we'll
// busy-loop forever.
int GtpuPipe::do_encap() {
    auto *state = encap_state.get();
#ifdef NDEBUG
#define HALT __LINE__
#else
#define HALT (({ if (GtpuPipe::trap_on_halt) __builtin_trap(); }), __LINE__)
#endif
    // Malicious user could've made us busy-loop if she resets consumer
    // cursor concurrently.  This is a low-effort attack as opposed to
    // actually sending packets at a high rate.
    if (state->rx.was_clobbered()) return HALT;

    uint64_t rx = 0;

    // Process rx ring.
    state->rx.reload();
    const auto n = std::min(state->rx.size(), batch_size);
    for (uint32_t i = 0; i != n; ++i) {
        auto desc = state->rx.load(i);
        auto [p, max_len] = xdp_umem.open_buf(desc.buf);
        if (!p || desc.len > max_len) return HALT;
        // Assume eth header.
        if (desc.len <= sizeof(ethhdr)) return HALT;
        state->iov[i * 2 + 1].iov_base = static_cast<uint8_t *>(p) + sizeof(ethhdr);
        state->gtpu[i].length = htons(state->iov[i * 2 + 1].iov_len = desc.len - sizeof(ethhdr));

        // Read current rx counter value (written by BPF into the packet header).
        rx = *static_cast<volatile uint64_t *>(p);
    }
    state->rx.advance(n);

    // Send frames out.  As we have mmsg_send / iov_send previously set up,
    // sendmmsg will do proper framing.
    // Note: we prepend gtpu header by having a 2-element iovec.  While we
    // could've reduced that to 1-element if we had rendered gtpu header
    // in the buf, that has security implications (malicious user might
    // clobber the buffer concurrently, resulting in the broken framing).
    ssize_t rc = sendmmsg(net_sock_.get(), &state->mmsg[0], n, MSG_DONTWAIT);

    // Retire frames (put back on umem_fill ring).
    state->umem_fill.reload();
    if (state->umem_fill.capacity() < n) return HALT;
    for (uint32_t i = 0; i < n; ++i) {
        auto page = xdp_umem.page_handle(state->iov[i * 2 + 1].iov_base);
        state->umem_fill.store(i, page);
    }
    state->umem_fill.advance(n);

    uint64_t ok = state->ok + std::max<ssize_t>(rc, 0);
    uint64_t drop_tx = state->drop_tx + n - std::max<ssize_t>(rc, 0);
    uint64_t drop_rx = state->drop_rx;

    if (state->bpf_state) {
        // A client might commit the following misdeads:
        //   * Not use the BPF program we provide; bogus Rx values in packets;
        //   * Not use our program; Rx counter in BPF state not updated.
        // As the countermeasure, we ensure that the Rx value in packets
        // are in the range [total number of packets so far, BPF state RX].
        uint64_t rx_max = state->bpf_state->rx;
        drop_rx = std::max(ok + drop_rx + drop_tx, std::min(rx, rx_max)) - ok - drop_tx;
    }

    gtpd_encap_update(
        cookie_,
        state->ok = ok,
        state->drop_rx = drop_rx,
        state->drop_tx = drop_tx
    );

    return 0;
}

static int gtpu_hdr_len(const volatile uint8_t *p, uint32_t len) {
    // len, type, ver, PT bit validated by tunnel dispatcher
    assert(len >= GTPU_FIXED_SIZE);

    // Buffer might be updated concurrently by a malicious client.
    // Therefore volatile.
    auto *hdr = reinterpret_cast<const volatile GtpuHeader *>(p);
    auto flags = hdr->ver_flags;

    if (0 == (flags & GTPU_E_S_PN_BIT)) return GTPU_FIXED_SIZE;

    if (len < sizeof(GtpuHeader)) return -1;

    if (0 == (flags & GTPU_E_BIT)) return sizeof(GtpuHeader);

    uint32_t offset = sizeof(GtpuHeader);
    uint8_t ext_type = hdr->next_ext_type;

    // Skip extension headers.
    while (ext_type) {
        if (len <= offset) return -1;
        uint8_t ehdr_len = 4 * p[offset];
        if (!ehdr_len || offset + ehdr_len <= len) return -1;
        offset += ehdr_len;
        ext_type = p[offset - 1];
    }

    return offset;
}

int GtpuPipe::do_decap() {
    auto *state = decap_state.get();

    // Re-fill buffers from completion ring (initially empty)
    state->umem_completion.reload();
    auto n = std::min(state->mmsg_offset, state->umem_completion.size());
    for (uint32_t i = 0; i < n; ++i) {
        auto *p = xdp_umem.open_buf(state->umem_completion.load(i));
        if (!p) return HALT;
        state->iov[--state->mmsg_offset].iov_base = p;
    }
    state->umem_completion.advance(n);

    // Re-fill buffers from free pages
    while (state->mmsg_offset && state->n_pages_free) {
        state->iov[--state->mmsg_offset].iov_base
            = xdp_umem.open_buf(xdp_umem.page(--state->n_pages_free));
    }

    // Receive next batch.
    // Note the number of frames in mmsg is 2x the batch size.  The
    // second half uses a dummy buffer.  Recieving into a dummy buffer
    // discards input.  Hopefully, we had enough buffers to re-fill
    // (mmsg_offset is zero).  If not, we'll potentially discard
    // the imput partially.  This is intentional.
    int rc = recvmmsg(net_sock_.get(), &state->mmsg[state->mmsg_offset], batch_size,
                      MSG_DONTWAIT, nullptr);
    if (rc <= 0) return 0;
    uint32_t mmsg_end_offset = std::min(state->mmsg_offset + rc, batch_size);

    // Counter deltas.
    uint32_t drop_rx = state->rxq_overflow_delta(state->mmsg_offset + rc - 1);
    uint32_t drop_tx = rc - (mmsg_end_offset - state->mmsg_offset);
    uint32_t trunc = 0;
    uint32_t bad = 0;

    // Forward frames to xdp sock.
    ethhdr eth = {};
    eth.h_dest[5] = eth.h_source[5] = 1; // 00:00:00:00:00:01
    eth.h_proto = static_cast<uint16_t>(inner_proto_);
    state->tx.reload();
    if (state->tx.capacity() < mmsg_end_offset - state->mmsg_offset) return HALT;
    uint32_t tx = 0;
    for (int i = state->mmsg_offset; i != mmsg_end_offset; ++i) {
        if (state->mmsg[i].msg_hdr.msg_flags & MSG_TRUNC) {
            ++trunc;
            continue;
        }
        uint8_t *p = static_cast<uint8_t*>(state->iov[i].iov_base);
        uint32_t len = state->mmsg[i].msg_len;
        int hdr_len = gtpu_hdr_len(p, len);
        if (hdr_len < 0) {
            // Mark as rejected.
            state->mmsg[i].msg_hdr.msg_flags = MSG_TRUNC;
            ++bad;
            continue;
        }
        len -= hdr_len;
        p += hdr_len;
        len += sizeof(eth);
        p -= sizeof(eth);
        memcpy(p, &eth, sizeof(eth));
        state->tx.store(tx++, XdpDesc(xdp_umem.buf_handle(p), len, 0));
    }
    if (tx) {
        state->tx.advance(tx);
        sendto(xdp_sock_.get(), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
    }

    // Shift rejected frames right and update mmsg_recv_offset.
    for (int i = mmsg_end_offset; i-- != state->mmsg_offset; ) {
        if (state->mmsg[i].msg_hdr.msg_flags & MSG_TRUNC) {
            state->iov[--mmsg_end_offset].iov_base = state->iov[i].iov_base;
        }
    }
    state->mmsg_offset = mmsg_end_offset;

    gtpd_decap_update(
        cookie_,
        state->ok += tx,
        state->drop_rx += drop_rx,
        state->drop_tx += drop_tx,
        state->bad += bad,
        state->trunc += trunc
    );

    return 0;
}

void GtpuPipe::on_tunnel_updated() {
    for (auto &gtpu: encap_state->gtpu)
        gtpu.teid = tunnel_.remote_teid();

    msghdr proto;
    tunnel_.set_outbound_msg_meta(&proto, &encap_state->msg_meta);
    for (auto &mm: encap_state->mmsg) {
        mm.msg_hdr.msg_name = proto.msg_name;
        mm.msg_hdr.msg_namelen = proto.msg_namelen;
        mm.msg_hdr.msg_control = proto.msg_control;
        mm.msg_hdr.msg_controllen = proto.msg_controllen;
    }
}

void GtpuPipe::on_inner_proto_updated() {
    encap_state->bpf_state->inner_proto = uint16_t(inner_proto_);
}

Fd GtpuPipe::xdp_bpf_prog(const Fd &xdp_sock, const BpfState &state) {
    Fd xsk_map = bpf_create_map(
        BPF_MAP_TYPE_XSKMAP, sizeof(int), sizeof(int), 1, 0
    );
    if (xdp_sock) { // check_xdp_bpf_prog_can_load doesn't pass a valid xdp_sock
        int ind_0 = 0, fd = xdp_sock.get();
        bpf_update_elem(xsk_map, &ind_0, &fd, BPF_NOEXIST);
    }

    enum { L_Drop, LabelCount };
    int labels[LabelCount];

    bpf_insn prog[] = {
        // Program receives a pointer to xdp_md, should call
        // bpf_redirect_map() to redirect the ingress packet.
        // Packet data pointer (xdp_md->data) is at ETH header.
        // See xdping_kern.c in Linux sources for reference.

        //// Get packet data pointer (r6) and validate packet len
        BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_ARG1, offsetof(xdp_md, data)),
        BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_ARG1, offsetof(xdp_md, data_end)),
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_6),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, sizeof(ethhdr)),
        BPF_JMP_REG(BPF_JGT, BPF_REG_3, BPF_REG_2, L_Drop),

        //// Get bpf encap state pointer (r0).
        BPF_LD_MAP_FD(BPF_REG_ARG1, state.fd.get()),
        BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
        BPF_MOV32_IMM(BPF_REG_3, 0),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
        BPF_STX_MEM(BPF_W, BPF_REG_ARG2, BPF_REG_3, 0),
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, L_Drop),

        //// Load h_proto (uint16_t) from ETH header and validate.
        BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6, offsetof(ethhdr, h_proto)),
        BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_0, offsetof(BpfStateData, inner_proto)),
        BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_2, L_Drop),

        //// Bump Rx counter (bpf encap state).
        BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, offsetof(BpfStateData, rx)),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),
        BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, offsetof(BpfStateData, rx)),

        //// Store Rx value in the packet (partially clobbering ETH header).
        BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),

        //// Redirect to XDP socket.
        BPF_LD_MAP_FD(BPF_REG_ARG1, xsk_map.get()),
        BPF_MOV32_IMM(BPF_REG_ARG2, 0),
        BPF_MOV64_IMM(BPF_REG_ARG3, XDP_DROP /* if lookup fails */),
        BPF_EMIT_CALL(BPF_FUNC_redirect_map),
        BPF_EXIT_INSN(),

        //// Drop packet
BPF_LABEL(L_Drop),
        BPF_MOV32_IMM(BPF_REG_0, XDP_DROP),
        BPF_EXIT_INSN()
    };

    return bpf_prog_load(
        BPF_PROG_TYPE_XDP, prog,
        bpf_resolve_labels(prog, sizeof(prog)/sizeof(prog[0]), labels),
        "GPL"
    );
}

#ifndef NDEBUG
int GtpuPipe::trap_on_halt = 0;
#endif

uint64_t GtpuPipe::encap_ok() const {
    return encap_state->ok;
}
uint64_t GtpuPipe::encap_drop_rx() const {
    return encap_state->drop_rx;
}
uint64_t GtpuPipe::encap_drop_tx() const {
    return encap_state->drop_tx;
}

uint64_t GtpuPipe::decap_ok() const {
    return decap_state->ok;
}
uint64_t GtpuPipe::decap_drop_rx() const {
    return decap_state->drop_rx;
}
uint64_t GtpuPipe::decap_drop_tx() const {
    return decap_state->drop_tx;
}
uint64_t GtpuPipe::decap_bad() const {
    return decap_state->bad;
}
uint64_t GtpuPipe::decap_trunc() const {
    return decap_state->trunc;
}
