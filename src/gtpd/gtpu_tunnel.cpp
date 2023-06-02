#include "gtpu_tunnel.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <system_error>

#include "bpf.h"
#include "bpf_insn.h"
#include "gtpu.h"

Fd gtpu_socket(AF address_family)
{
    union {
        sockaddr_in v4;
        sockaddr_in6 v6;
    } addr = {};
    socklen_t addr_len = 0;

    switch (address_family) {
    case AF::INET:
        addr_len = sizeof(addr.v4);
        addr.v4.sin_family = AF_INET;
        addr.v4.sin_addr.s_addr = INADDR_ANY;
        addr.v4.sin_port = htons(GTPU_PORT);
        break;
    case AF::INET6:
        addr_len = sizeof(addr.v6);
        addr.v6.sin6_family = AF_INET6;
        addr.v6.sin6_addr = in6addr_any;
        addr.v6.sin6_port = htons(GTPU_PORT);
        break;
    }

    Fd fd(socket(static_cast<int>(address_family), SOCK_DGRAM, 0));
    int t = 1;
    if (fd
        && setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)) == 0
        && setsockopt(fd.get(), SOL_SOCKET, SO_REUSEPORT, &t, sizeof(t)) == 0
        && bind(fd.get(), reinterpret_cast<sockaddr *>(&addr), addr_len) == 0)
        return fd;

    throw std::system_error(errno, std::generic_category(),
                            "Create and configure GTPU socket");
}

GtpuTunnel::GtpuTunnel(const ApiGtpuTunnel &api) {
    data.address_family = api.address_family;
    data.remote_teid = api.remote_teid;
    switch (address_family()) {
    case AF::INET:
        data.remote.s_addr = api.remote.ip;
        data.local.s_addr = api.local.ip;
        data.local_teid = api.local_teid;
        return;
    case AF::INET6:
        memcpy(&data.remote6, api.remote.ip6, sizeof(data.remote6));
        memcpy(&data.local6, api.local.ip6, sizeof(data.local6));
        data.local_teid6 = api.local_teid;
        return;
    }
    throw std::system_error(EINVAL, std::generic_category());
}

ApiGtpuTunnel GtpuTunnel::api_gtpu_tunnel() const {
    ApiGtpuTunnel api = {};
    api.address_family = data.address_family;
    api.remote_teid = data.remote_teid;
    switch (address_family()) {
    case AF::INET:
        api.remote.ip = data.remote.s_addr;
        api.local.ip = data.local.s_addr;
        api.local_teid = data.local_teid;
        return api;
    case AF::INET6:
        memcpy(api.remote.ip6, &data.remote6, sizeof(data.remote6));
        memcpy(api.local.ip6, &data.local6, sizeof(data.local6));
        api.local_teid = data.local_teid6;
        return api;
    }
    __builtin_unreachable();
}

void GtpuTunnel::set_outbound_msg_meta(msghdr *m, MsgMetaStorage *s) const {
    auto* cmsg = reinterpret_cast<cmsghdr*>(&s->pktinfo_cmsg_buf);
    in_pktinfo pktinfo = {};
    in6_pktinfo pktinfo6 = {};

    switch (address_family()) {
    case AF::INET:
        // dest
        m->msg_name = &s->addr;
        m->msg_namelen = sizeof(s->addr);
        s->addr.sin_family = AF_INET;
        s->addr.sin_port = htons(GTPU_PORT);
        s->addr.sin_addr = data.remote;

        // src
        m->msg_control = cmsg;
        m->msg_controllen = CMSG_SPACE(sizeof(pktinfo));
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(pktinfo));
        pktinfo.ipi_spec_dst = data.local;
        memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
        break;

    case AF::INET6:
        // dest
        m->msg_name = &s->addr6;
        m->msg_namelen = sizeof(s->addr6);
        s->addr6.sin6_family = AF_INET6;
        s->addr6.sin6_port = htons(GTPU_PORT);
        s->addr6.sin6_flowinfo = 0;
        s->addr6.sin6_addr = data.remote6;
        s->addr6.sin6_scope_id = 0;

        // src
        m->msg_control = cmsg;
        m->msg_controllen = CMSG_SPACE(sizeof(pktinfo6));
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(pktinfo6));
        pktinfo6.ipi6_addr = data.local6;
        memcpy(CMSG_DATA(cmsg), &pktinfo6, sizeof(pktinfo6));
        break;
    }
}

SocketRegistration::SocketRegistration(const Fd& sock)
    : bpf_sockarray(bpf_create_map(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
                                   sizeof(int), sizeof(int), 1,
                                   BPF_F_WRONLY | BPF_F_RDONLY_PROG
      )) {
    int ind0 = 0, fd = sock.get();
    bpf_update_elem(bpf_sockarray, &ind0, &fd, BPF_NOEXIST);
}

unsigned GtpuTunnelDispatcher::initial_capacity = 32;

GtpuTunnelDispatcher::GtpuTunnelDispatcher(AF af, unsigned cap) noexcept
    : address_family(af), capacity(cap),
      key_to_sockarray(bpf_create_map(
        BPF_MAP_TYPE_HASH_OF_MAPS, GtpuTunnel::bpf_key_size(af), sizeof(int), cap,
        BPF_F_WRONLY | BPF_F_RDONLY_PROG,
        bpf_create_map(
            BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, sizeof(int), sizeof(int), 1,
            BPF_F_WRONLY | BPF_F_RDONLY_PROG
        )
      )) {}

bool GtpuTunnelDispatcher::register_tunnel(const GtpuTunnel& tunnel,
                                           const SocketRegistration& reg) {
    assert(address_family == tunnel.address_family());
    if (size == capacity) return false;
    int fd = reg.bpf_sockarray.get();
    bpf_update_elem(key_to_sockarray, tunnel.bpf_key().data(), &fd, BPF_NOEXIST);
    ++size;
    return true;
}

void GtpuTunnelDispatcher::unregister_tunnel(const GtpuTunnel& tunnel) noexcept {
    assert(address_family == tunnel.address_family());
    bpf_delete_elem(key_to_sockarray, tunnel.bpf_key().data());
    --size;
}

// Create packet dispatch program.
//
// key_to_sockarray: BPF_MAP_TYPE_HASH_OF_MAPS
// +------------------------+---+
// | gtpu_tunnel1.bpf_key() |   |      SocketRegistration
// | gtpu_tunnel2.bpf_key() | *------> BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
// |      .  .  .  .        |   |      +------+
// +------------------------+---+      | sock |
//                                     +------+
//
// sockarray_default:
// SocketRegistration BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
// +------+
// | sock |
// +------+
//
// The program attempts to match an inbound packet with a tunnel using
// key_to_sockarray.  If the match is found, pass to key_to_sockarray[key][0].
// If a packet is valid but doesn't map to a tunnel, pass to
// sockarray_default[0].
static Fd gtpu_reuseport_prog(AF address_family,
                             const Fd& key_to_sockarray,
                             const Fd& sockarray_default)
{
    // offset, size of <src,dest> address pair in the packet
    int src_dest_offset = 0, src_dest_len = 0;
    switch (address_family) {
    case AF::INET:
        src_dest_offset = offsetof(iphdr, saddr);
        src_dest_len = 8;
        break;
    case AF::INET6:
        src_dest_offset = offsetof(ipv6hdr, saddr);
        src_dest_len = 32;
        break;
    }

    enum {
        L_Drop, L_DoGtpuHeader, L_UseSockArrayDefault, L_FetchFromSockArray,
        L_NonLinear, LabelCount
    };
    int labels[LabelCount];

    bpf_insn prog[] = {
        // Program receives a pointer to sk_reuseport_md, should call
        // bpf_sk_select_reuseport() to select a destination socket.
        // Packet data pointer (sk_reuseport_md->data) is at UDP header.
        // See test_select_reuseport_kern.c in Linux sources for
        // reference.
        BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1),

        //// Get packet data pointer (r2) and validate packet len, don't clobber r1
        BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_CTX, offsetof(sk_reuseport_md, data)),
        BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_CTX, offsetof(sk_reuseport_md, data_end)),
        BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, sizeof(udphdr) + 8),
        BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, L_NonLinear),

        //// Check GTPU version and type, don't clobber r1
        //// Data pointer (r2) could point into the stack and r3, r4
        //// might be clobbered if we are coming from L_NonLinear
BPF_LABEL(L_DoGtpuHeader),
        BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_2, sizeof(udphdr)),
        BPF_ALU32_IMM(BPF_AND, BPF_REG_3,
                      htons(((GTPU_VER_MASK | GTPU_PT_BIT) << 8) | 255)),
        BPF_JMP32_IMM(BPF_JNE, BPF_REG_3,
                      htons(((GTPU_V1_VER | GTPU_PT_BIT) << 8) | GTPU_TYPE_GPDU),
                      L_UseSockArrayDefault),

        //// Make key (at fp-src_dest_len-4)
        BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_2, sizeof(udphdr) + 4), // teid
        BPF_STX_MEM(BPF_W, BPF_REG_FP, BPF_REG_2, -4),
        // bpf_skb_load_bytes_relative(reuse_md, <offset>,
        //                             fp-KEYMAX_SIZE+4, <len>, BPF_HDR_START_NET)
        // reuse_md still in r1
        BPF_MOV32_IMM(BPF_REG_ARG2, src_dest_offset),
        BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -src_dest_len - 4),
        BPF_MOV32_IMM(BPF_REG_ARG4, src_dest_len),
        BPF_MOV32_IMM(BPF_REG_ARG5, BPF_HDR_START_NET),
        BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes_relative),
        BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 0, L_Drop),

        //// Lookup SocketRegistration (sockarray) by key
        BPF_LD_MAP_FD(BPF_REG_ARG1, key_to_sockarray.get()),
        BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -src_dest_len - 4),
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, L_UseSockArrayDefault),

        //// Fetch socket #0 from sockarray
        BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_0),
BPF_LABEL(L_FetchFromSockArray),
        BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_CTX),
        BPF_MOV32_IMM(BPF_REG_ARG4, 0),
        // r3 = fp - 4; *(int *)r3 = 0
            BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -4),
            BPF_STX_MEM(BPF_W, BPF_REG_ARG3, BPF_REG_ARG4, 0),
        BPF_EMIT_CALL(BPF_FUNC_sk_select_reuseport),
        // r0 = 0 on success, set to SK_PASS (1)
        BPF_MOV32_IMM(BPF_REG_0, SK_PASS),
        BPF_EXIT_INSN(),

        //// Drop packet
BPF_LABEL(L_Drop),
        BPF_MOV32_IMM(BPF_REG_0, SK_DROP),
        BPF_EXIT_INSN(),

        //// Use sockarray_default
BPF_LABEL(L_UseSockArrayDefault),
        BPF_LD_MAP_FD(BPF_REG_ARG2, sockarray_default.get()),
        BPF_JMP_A(L_FetchFromSockArray),

        //// Handle non-linear buffer (or a short packet);
        //// both have (md->data_end - md->data) less than we expect.
BPF_LABEL(L_NonLinear),
        // bpf_skb_load_bytes(reuse_md, 0,
        //                    fp - sizeof(udphdr) - 8, sizeof(udphdr) + 8)
        BPF_MOV32_IMM(BPF_REG_ARG2, 0),
            BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_FP),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -int(sizeof(udphdr)) - 8),
        BPF_MOV32_IMM(BPF_REG_ARG4, int(sizeof(udphdr)) + 8),
        BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),
        BPF_JMP32_IMM(BPF_JNE, BPF_REG_0, 0, L_Drop),

        // Restore things to the state L_DoGtpuHeader expects
        BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_CTX),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_FP),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -int(sizeof(udphdr)) - 8),
        BPF_JMP_A(L_DoGtpuHeader),
    };

    return bpf_prog_load(BPF_PROG_TYPE_SK_REUSEPORT, prog,
                         bpf_resolve_labels(prog, sizeof(prog)/sizeof(prog[0]), labels),
                         "GPL");
}

void GtpuTunnelDispatcher::activate(const Fd& sock, const SocketRegistration &reg) {
    uint32_t fd = sock.get();

    Fd bpf_prog(gtpu_reuseport_prog(address_family, key_to_sockarray, reg.bpf_sockarray));
    int prog_fd = bpf_prog.get();
    if (setsockopt(sock.get(), SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                    &prog_fd, sizeof(prog_fd)) != 0)
        throw std::system_error(errno, std::generic_category(),
                                "Attach BPF reuseport program");
}
