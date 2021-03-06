#pragma once
#include "common/fd.h"
#include "gtpu_tunnel.h"
#include "xdp.h"

// Protocol inside the tunnel.  Used uninterpreted to fill in or
// check ethertype in Ethernet header in veth link accessed via XDP
// socket.  Common values include htons(ETH_P_IP) and htons(ETH_P_IPV6).
enum class InnerProto: uint16_t {};

// Opaque integer id; zero is invalid.
enum class GtpuTunnelId: uint32_t {};

// Receives on XDP socket, GTPU encapsulates, and sends on NET (UDP)
// socket.  Also receives on NET, decapsulates, and sends on XDP.
//
// The class itself doesn't subscribe for the readiness notifications
// for the respective file descriptors; the user should take care of
// invoking do_decap() and do_encap() when appropriate.
struct GtpuPipe {
    struct Options {
        int encap_mtu = 1500 - 40 - 8; // MTU, taking encapsulation overhead into account
        int batch_size = 128;          // number of packets exchanged in a batch
        int xdp_pool_size = 512;       // number of pages in XDP pool
    };

private:
    struct EncapState;

public:
    class BpfState {
        friend struct GtpuPipe;
        friend struct EncapState;
        Fd fd;
    public:
        BpfState();
    };

    // XDP socket requires a BPF program to be installed in a network
    // interface to receive ingress traffic.  Produce such a program.
    static Fd xdp_bpf_prog(const Fd &xdp_sock, const BpfState &state);

    // dry run: ensure that XDP program loads successfully
    static void check_xdp_bpf_prog_can_load() {
        xdp_bpf_prog(Fd(), BpfState());
    }

    GtpuPipe(const GtpuTunnel &tunnel, Fd net_sock, Fd xdp_sock,
             InnerProto inner_proto,
             const Options &opts,
             BpfState bpf_state);

    ~GtpuPipe();

    const Fd &net_sock() const { return net_sock_; }
    void set_net_sock(Fd net_sock);

    const Fd &xdp_sock() const { return xdp_sock_; }

    const GtpuTunnel &tunnel() const { return tunnel_; }
    void set_tunnel(const GtpuTunnel &tunnel) {
        tunnel_ = tunnel;
        on_tunnel_updated();
    }

    InnerProto inner_proto() const { return inner_proto_; }
    void set_inner_proto(InnerProto inner_proto) {
        inner_proto_ = inner_proto;
        on_inner_proto_updated();
    }

    int do_encap(GtpuTunnelId id);

    int do_decap(GtpuTunnelId id);

    // Counters.
    uint64_t encap_ok() const;
    uint64_t encap_drop_rx() const;
    uint64_t encap_drop_tx() const;

    uint64_t decap_ok() const;
    uint64_t decap_drop_rx() const;
    uint64_t decap_drop_tx() const;
    uint64_t decap_bad() const;
    uint64_t decap_trunc() const;

private:
    struct EncapState;
    struct DecapState;

    GtpuTunnel tunnel_;
    Fd net_sock_, xdp_sock_;
    InnerProto inner_proto_;
    const uint32_t batch_size;

    XdpUmem xdp_umem;

    std::unique_ptr<EncapState> encap_state;
    std::unique_ptr<DecapState> decap_state;

private:
    GtpuPipe(const GtpuTunnel &tunnel, Fd &net_sock, Fd &xdp_sock,
             InnerProto inner_proto,
             const Options &opts,
             xdp_mmap_offsets mmap_ofsets,
             BpfState bpf_state);

    void on_tunnel_updated();
    void on_inner_proto_updated();

#ifndef NDEBUG
    // Invoke trap when pipe is halted. (Enable via gdb.)
    static int trap_on_halt;
#endif
};
