#include "cmdline.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sstream>
#include <string_view>
#include <system_error>
#include <tuple>

namespace {

static const char err_ip_ipv6_mismatch[] = "IP/IPv6 mismatch";
static const char err_duplicate_argument[] = "Duplicate argument";
static const char err_unexpected_argument[] = "Unexpected argument";

// CmdLineSegment tracks the current argument in the command line.
// Additionally, it tracks position of the "statement start", e.g.
// as in 'set frob 42'.
//
// The parsing logic sees 'set' first.  It recognises the command
// and expects more tokens to follow.  It calls 'advance()', making
// 'frob' the current token.  Statement start position is unchanged,
// the whole statement now reads 'set frob'.  The parser recognises
// 'frob' and expects another token.  Subsequent 'advance()' makes
// '42' the current token, and the statement reads 'set frob 42'.
//
// The parser invokes a reusable routine to convert the argument.
// Imagine that conversion fails.  As the statement provides enough
// context, the conversion routine itself can report the error,
// yielding something similar to "'set frob 42': Invalid argument, lit required"
//
// Similarly, advance() reports a problem if command line ends
// prematurely. e.g. "'set frob': Argument required".
struct CmdLineSeg {
    CmdLineSeg() {}
    explicit CmdLineSeg(const char *const *argv) {
        if (*argv) { begin = argv; end = argv + 1; }
    }
    operator bool() const { return begin != end; }
    std::string_view current() const { return end[-1]; }
    void advance() {
        if (!*end) err("Argument required");
        ++end;
    }
    CmdLineSeg next() const { return CmdLineSeg(end); }
    void err(std::string_view msg) const {
        std::ostringstream s;
        if (*this) {
            s << '\'';
            for (const char *const *p = begin;; ) {
                s << *p;
                if (++p == end) break;
                s << ' ';
            }
            s << "': ";
        }
        s << msg;
        throw std::runtime_error(s.str());
    }
    uint32_t parse_u32() const {
        char *reject;
        errno = 0;
        auto v = strtoul(end[-1], &reject, 10);
        if (errno || *reject || v > std::numeric_limits<uint32_t>::max())
            err("Invalid argument, decimal integer required");
        return static_cast<uint32_t>(v);
    }
    uint32_t parse_ip(ApiAddr *addr, uint32_t expected_af) const {
        uint32_t af;
        if (inet_pton(AF_INET, end[-1], &addr->ip))
            af = AF_INET;
        else if (inet_pton(AF_INET6, end[-1], &addr->ip6))
            af = AF_INET6;
        else
            err("Invalid argument, IP or IPv6 address required");
        if (expected_af && af != expected_af)
            err(err_ip_ipv6_mismatch);
        return af;
    }
private:
    const char *const *begin = nullptr, *const *end = nullptr;
};

// GtpuTunnelParser recognises GTPU tunnel attribute keywords
// and stores parsed attribute values into designated location.
struct GtpuTunnelParser {

    explicit GtpuTunnelParser(ApiGtpuTunnel *p): tun(p) {}

    CmdLineSeg local, remote, local_teid, remote_teid;

    bool consume(CmdLineSeg *s) {
        if (s->current() == "local")
            return consume_local_or_remote(LOCAL, s);
        if (s->current() == "remote")
            return consume_local_or_remote(REMOTE, s);
        if (s->current() == "local-teid")
            return consume_teid(LOCAL, s);
        if (s->current() == "remote-teid")
            return consume_teid(REMOTE, s);
        return false;
    }

    void check_required_fields() {
        if (!local)
            throw std::runtime_error("Local address required, "
                                     "e.g. 'local 1.2.3.4'");
        if (!remote)
            throw std::runtime_error("Remote address required, "
                                     "e.g. 'remote 1.2.3.4'");
    }

private:
    enum LocalOrRemote { LOCAL, REMOTE };

    bool consume_local_or_remote(LocalOrRemote lor, CmdLineSeg *s) {
        auto &loc = lor == LOCAL ? local : remote;
        auto *dest = lor == LOCAL ? &tun->local : &tun->remote;
        s->advance();
        tun->address_family = s->parse_ip(dest, tun->address_family);
        if (loc) s->err(err_duplicate_argument);
        loc = *s;
        *s = s->next();
        return true;
    }

    bool consume_teid(LocalOrRemote lor, CmdLineSeg *s) {
        auto &loc = lor == LOCAL ? local_teid : remote_teid;
        auto *dest = lor == LOCAL ? &tun->local_teid : &tun->remote_teid;
        s->advance();
        *dest = htonl(s->parse_u32());
        if (loc) s->err(err_duplicate_argument);
        loc = *s;
        *s = s->next();
        return true;
    }

    ApiGtpuTunnel *tun;
};

// InnerProtoParser recognises 'type ip' and 'type ipv6' statements,
// and stores the type in desinated location.
struct InnerProtoParser {

    explicit InnerProtoParser(uint32_t *p): inner_proto(p) {}

    CmdLineSeg loc;

    bool consume(CmdLineSeg *s) {
        if (s->current() != "type") return false;
        s->advance();
        if (s->current() == "ip")
            *inner_proto = htons(ETH_P_IP);
        else if (s->current() == "ipv6")
            *inner_proto = htons(ETH_P_IPV6);
        else
            s->err("Invalid argument, 'ip' or 'ipv6' required");
        if (loc) s->err(err_duplicate_argument);
        loc = *s;
        *s = s->next();
        return true;
    }

private:
    uint32_t *inner_proto;
};

// Parses arguments of create session command amd Produces
// ApiCreateGtpuTunnel message + device name.
std::pair<ApiCreateGtpuTunnelMsg, const char *>
parse_create_gtpu_tunnel_cmd(CmdLineSeg s) {

    ApiCreateGtpuTunnelMsg msg = {};
    msg.length = sizeof(msg);
    msg.code = API_CREATE_GTPU_TUNNEL_CODE;
    msg.inner_proto = htons(ETH_P_IP);

    GtpuTunnelParser tun_parser(&msg.tunnel);
    InnerProtoParser inner_proto_parser(&msg.inner_proto);

    const char *if_name = nullptr;
    bool cookie_set = false;

    while (s) {
        if (tun_parser.consume(&s)) continue;
        if (inner_proto_parser.consume(&s)) continue;
        if (s.current() == "dev") {
            s.advance();
            if (if_name) s.err(err_duplicate_argument);
            if_name = s.current().data();
            s = s.next();
            continue;
        }
        if (s.current() == "cookie") {
            s.advance();
            if (cookie_set) s.err(err_duplicate_argument);
            msg.cookie = s.parse_u32();
            s = s.next();
            continue;
        }
        s.err(err_unexpected_argument);
    }

    tun_parser.check_required_fields();

    if (!if_name)
        throw std::runtime_error("Device name required, e.g. 'dev foo'");

    return { msg, if_name };
}

// Parses arguments of delete session command.
ApiDeleteGtpuTunnelMsg parse_delete_gtpu_tunnel_cmd(CmdLineSeg s) {

    ApiDeleteGtpuTunnelMsg msg = {};
    msg.length = sizeof(msg);
    msg.code = API_DELETE_GTPU_TUNNEL_CODE;

    GtpuTunnelParser key_tun_parser(&msg.tunnel);

    while (s) {
        if (!key_tun_parser.consume(&s)) s.err(err_unexpected_argument);
    }

    key_tun_parser.check_required_fields();

    return msg;
}

// Parses arguments of modify session command.
ApiModifyGtpuTunnelMsg parse_modify_gtpu_tunnel_cmd(CmdLineSeg s) {

    ApiModifyGtpuTunnelMsg msg = {};
    msg.length = sizeof(msg);
    msg.code = API_MODIFY_GTPU_TUNNEL_CODE;

    GtpuTunnelParser key_tun_parser(&msg.tunnel);
    GtpuTunnelParser new_tun_parser(&msg.new_tunnel);
    InnerProtoParser new_inner_proto_parser(&msg.new_inner_proto);

    while (s) {
        if (key_tun_parser.consume(&s)) continue;
        if (s.current() == "set") {
            s.advance();
            if (!new_tun_parser.consume(&s)
                && !new_inner_proto_parser.consume(&s)
            ) s.err(err_unexpected_argument);
            continue;
        }
        s.err(err_unexpected_argument);
    }

    key_tun_parser.check_required_fields();

    if (new_tun_parser.local || new_tun_parser.remote
        || new_tun_parser.local_teid || new_tun_parser.remote_teid) {

        msg.flags |= API_MODIFY_GTPU_TUNNEL_TUNNEL_FLAG;

        if (!new_tun_parser.local_teid)
            msg.new_tunnel.local_teid = msg.tunnel.local_teid;

        if (!new_tun_parser.remote_teid)
            msg.new_tunnel.remote_teid = msg.tunnel.remote_teid;

        uint32_t local_af = msg.new_tunnel.address_family;
        uint32_t remote_af = msg.new_tunnel.address_family;

        if (!new_tun_parser.local) {
            msg.new_tunnel.local = msg.tunnel.local;
            local_af = msg.tunnel.address_family;
        }

        if (!new_tun_parser.remote) {
            msg.new_tunnel.remote = msg.tunnel.remote;
            remote_af = msg.tunnel.address_family;
        }

        if (local_af != remote_af)
            (new_tun_parser.local ? new_tun_parser.local
            : new_tun_parser.remote).err(err_ip_ipv6_mismatch);

        msg.new_tunnel.address_family = local_af;
    }

    if (new_inner_proto_parser.loc)
        msg.flags |= API_MODIFY_GTPU_TUNNEL_INNER_PROTO_FLAG;

    return msg;
}

} // namespace

std::pair<ApiMsg, const char*> parse_args(const char * const *argv) {
    ApiMsg msg = {};
    const char *if_name = nullptr;
    CmdLineSeg s(argv);
    if (s) {
        if (s.current() == "add") {
            std::tie(msg.create_gtpu_tunnel, if_name)
                = parse_create_gtpu_tunnel_cmd(s.next());
        } else if (s.current() == "del") {
            msg.delete_gtpu_tunnel
                = parse_delete_gtpu_tunnel_cmd(s.next());
        } else if (s.current() == "mod") {
            msg.modify_gtpu_tunnel
                = parse_modify_gtpu_tunnel_cmd(s.next());
        } else if (s.current() == "ls") {
            if (s.next()) s.next().err(err_unexpected_argument);
            auto &ls = msg.list_gtpu_tunnels;
            ls.length = sizeof(ls);
            ls.code = API_LIST_GTPU_TUNNELS_CODE;
        }
    }
    if (!msg.code) s.err("Expected 'add', 'del', 'mod' or 'ls'");
    return { msg, if_name };
}
