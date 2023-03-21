#pragma once
#include "common/fd.h"
#include "gtpd/api.h"
#include <arpa/inet.h>
#include <cassert>
#include <memory>
#include <string_view>
#include <limits>

enum class AddressFamily { INET = AF_INET, INET6 = AF_INET6 };
using AF = AddressFamily;

// Create UDP socket and bind to GTPU port.
Fd gtpu_socket(AF address_family);

// GtpuTunnel: a contrived encoding to meet certain runtime requirements.
//
// In a set of GTPU tunnels, both <local, remote, local_teid> and
// <local, remote, remote_teid> must be unique (local/remote is the
// corresponding ip/ipv6 address).
//
// A hash table keyed by <l,r,l_teid> is used to dispatch inbound
// data packets apertaining a certain tunnel.  Another one keyed by
// <l,r,r_teid> is necessary to handle inbound error indications.
// (Error indication is generated whenever a remote receives a data packet
// it doesn't have a matching tunnel configured.)
//
// For performance reasons, data packets dispatch is done in kernel
// using BPF.  Therefore the hash table keyed by <l,r,l_teid> is
// maintained as a BPF map.  Application state is maintained in a hash
// table keyed by <l,r,r_teid>.  GtpuTunnel layout is optimised to
// produce a key and bpf_key (as std::u32string_view) without copying.
class GtpuTunnel
{
    struct GtpuTunnelData
    {
        // Field order and the lack of padding is important, see key() and bpf_key().
        uint32_t address_family;
        uint32_t remote_teid;
        union {
            struct { // Consistent with gtpu_reuseport_prog().
                in_addr remote, local;
                uint32_t local_teid;
            };
            struct { // Consistent with gtpu_reuseport_prog().
                in6_addr remote6, local6;
                uint32_t local_teid6;
            };
        };
    };

    GtpuTunnelData data;

public:
    explicit GtpuTunnel(const ApiGtpuTunnel &rpc);

    ApiGtpuTunnel api_gtpu_tunnel() const;

    AF address_family() const {
        return static_cast<AF>(data.address_family);
    }

    uint32_t local_teid() const {
        switch (address_family()) {
        case AF::INET: return data.local_teid;
        case AF::INET6: return data.local_teid6;
        }
        __builtin_unreachable();
    }

    uint32_t remote_teid() const { return data.remote_teid; }

    std::u32string_view key() const {
        static_assert(sizeof(char32_t) == sizeof(uint32_t));
        auto *base = reinterpret_cast<const char32_t *>(&data.address_family);
        switch (address_family()) {
        case AF::INET: return { base, 4 };
        case AF::INET6: return { base, 10 };
        }
        __builtin_unreachable();
    }

    std::u32string_view bpf_key() const {
        static_assert(sizeof(char32_t) == sizeof(uint32_t));
        auto *base = reinterpret_cast<const char32_t *>(&data.remote);
        switch (address_family()) {
        case AF::INET: return { base, 3 };
        case AF::INET6: return { base, 9 };
        }
        __builtin_unreachable();
    }

    static unsigned bpf_key_size(AF address_family) {
        switch (address_family) {
        case AF::INET: return 12;
        case AF::INET6: return 36;
        }
        __builtin_unreachable();
    }

    struct MsgMetaStorage {
        union {
            sockaddr_in addr;
            sockaddr_in6 addr6;
        };
        union alignas(cmsghdr) {
            uint8_t pktinfo_cmsg_buf[CMSG_SPACE(sizeof(in_pktinfo))];
            uint8_t pktinfo6_cmsg_buf[CMSG_SPACE(sizeof(in6_pktinfo))];
        };
    };

    // Using sockets bound to INADDR_ANY, therefore it is necessary
    // to specify both the source and destination addresses,
    void set_outbound_msg_meta(msghdr *m, MsgMetaStorage *s) const;
};

inline bool operator==(const GtpuTunnel& a, const GtpuTunnel& b) {
    return a.key() == b.key() && a.local_teid() == b.local_teid();
}

struct SocketRegistration;

// GtpuTunnelDispatcher manages in-kernel state used to dispatch inbound
// packets to the correct socket.
//
// Internally, the following structure of BPF maps is built:
//
// key_to_sockarray: BPF_MAP_TYPE_HASH_OF_MAPS
// +------------------------+---+
// | gtpu_tunnel1.bpf_key() |   |      SocketRegistration
// | gtpu_tunnel2.bpf_key() | *------> BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
// |      .  .  .  .        |   |      +------+
// +------------------------+---+      | sock |
//                                     +------+
//
// The root hash table maps each registered GTPU tunnel key
// (<local,remote,local_teid>) to a "SocketRegistration". The later is
// BPF_MAP_TYPE_REUSEPORT_SOCKARRAY of size 1.
//
// * * *
//
// All GTPU sockets should be produced by gtpu_socket().  All sockets
// are bound to <INADDR_ANY, GTPU_PORT>, and end up in a reuseport
// group.  A BPF program routes inbound packet to the correct socket.
//
// The intended usage is as follows.  It is assumed that one bound GTPU
// socket exists per address family (aka server socket).  If the
// matching tunnel is not found for inbound packet, it is routed to the
// server socket.
//
// auto server_sock = gtpu_socket(AF::INET);
// auto dispatcher = GtpuTunnelDispatcher::create(AF::INET);
// dispatcher->activate(server_sock, SocketRegistration(server_sock));
//
// When a tunnel is requested, additional GTPU socket is created and
// bound to the same port/address as the server socket.  The dispatcher
// is updated accordingly:
//
// auto sock = gtpu_sock(AF::INET);
// dispatcher->register_tunnel(tunnel, SocketRegistration(sock));
//
// Once it's time to get rid of the tunnel:
//
// dispatcher.unregister_tunnel(tunnel);
//
// There's a quirk: a dispatcher has fixed capacity.  If the capacity is
// exceeded, it is necessary to create a larger dispatcher
// /dispatcher.create_next_capacity()/, transfer registrations manually,
// and finally activate the new dispatcher.
//
// Note: keep track of registrations as they are needed when
// transferring to a larger dispatcher and an attempt to create a second
// one will fail.
struct GtpuTunnelDispatcher {
    GtpuTunnelDispatcher(AF af, unsigned cap) noexcept;

    // Arrange for inbound datagrams matching the tunnel to get
    // delivered to the specified socket.  A dispatcher has fixed
    // capacity; if reached, RegisterTunnel returns false.  The method
    // may throw if failing for other reasons.
    bool register_tunnel(const GtpuTunnel& tunnel, const SocketRegistration &reg);

    void unregister_tunnel(const GtpuTunnel& tunnel) noexcept;

    // Create a larger dispatcher; registrations aren't transferred.
    std::unique_ptr<GtpuTunnelDispatcher> create_next_capacity() const {
        if (capacity > std::numeric_limits<decltype(capacity)>::max() / 2)
            throw std::bad_alloc();
        return std::make_unique<GtpuTunnelDispatcher>(address_family, capacity * 2);
    }

    void activate(const Fd& sock, const SocketRegistration &reg);

    static std::unique_ptr<GtpuTunnelDispatcher> create(AF address_family) {
        return std::make_unique<GtpuTunnelDispatcher>(address_family, initial_capacity);
    }

    static unsigned initial_capacity;

private:
    AF address_family;
    unsigned capacity, size = 0;
    Fd key_to_sockarray;
};

struct SocketRegistration {
    friend struct GtpuTunnelDispatcher;
    SocketRegistration() {}
    explicit SocketRegistration(const Fd& sock);
private:
    Fd bpf_sockarray;
};
