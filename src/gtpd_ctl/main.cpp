// gtpd_ctl add local 1.1.1.1 local-teid 1234 remote 2.2.2.2 remote-teid 1234
//          dev veth-tun type ip
// gtpd_ctl del 1
// gtpd_ctl mod 1 set local-teid 42 set type ipv6
// gtpd_ctl ls

#include "api_client.h"
#include "cmdline.h"
#include "common/version.h"
#include <arpa/inet.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <system_error>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>

static void print_tunnels(const std::vector<ApiGtpuTunnelListItemMsg> &list);
static int bpf_set_link_xdp_fd(int ifindex, int fd, uint32_t flags);

struct CmdHandler {
    ApiClient client;

    CmdHandler(const char *sock_path): client(sock_path) {}

    int operator() (const CreateGtpuTunnelCmd &cmd) {
        unsigned if_index = if_nametoindex(cmd.if_name);
        if (!if_index) {
            throw std::system_error(errno, std::generic_category(),
                                    std::string("Device '")
                                    + cmd.if_name + "'");
        }

        Fd xdp_sock(socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0));
        if (!xdp_sock) {
            throw std::system_error(errno, std::generic_category(),
                                    "Creating XDP socket");
        }

        Fd pidfd;
        if (cmd.session_leader_pid != -1) {
            pidfd = Fd(syscall(SYS_pidfd_open, cmd.session_leader_pid, 0));
            if (!pidfd) {
                throw std::system_error(
                    errno, std::generic_category(),
                    "Obtaining pidfd for process " + std::to_string(cmd.session_leader_pid)
                );
            }
        }

        auto [id, bpf_prog] = client.create_gtpu_tunnel(cmd.msg, xdp_sock, pidfd);

        // Bind xdp_sock to the interface
        struct sockaddr_xdp addr = {};
        addr.sxdp_family = AF_XDP;
        addr.sxdp_ifindex = if_index;
        addr.sxdp_queue_id = 0;
        if (bind(xdp_sock.get(), reinterpret_cast<sockaddr *>(&addr),
                  sizeof(addr)) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "Bind XDP socket");;
        }

        // Install xdp_prog
        int error = bpf_set_link_xdp_fd(if_index, bpf_prog.get(), 0);
        if (error != 0) {
            throw std::system_error(-error, std::generic_category(),
                                    "Install XDP BPF program");;
        }

        printf("%d\n", id);
        return EXIT_SUCCESS;
    }

    int operator() (const DeleteGtpuTunnelCmd &cmd) {
        client.delete_gtpu_tunnel(cmd.msg);
        return EXIT_SUCCESS;
    }

    int operator() (const ModifyGtpuTunnelCmd &cmd) {
        client.modify_gtpu_tunnel(cmd.msg);
        return EXIT_SUCCESS;
    }

    int operator() (const ListGtpuTunnelsCmd &cmd) {
        print_tunnels(client.list_gtpu_tunnels(cmd.msg));
        return EXIT_SUCCESS;
    }
};

int main(int argc, const char *const *argv) {

    int opt;
    while ((opt = getopt(argc, const_cast<char * const *>(argv), "hv")) != -1) {
        switch (opt) {
        default:
            return EXIT_FAILURE;
        case 'v':
            printf("gtpd_ctl %s\n", version);
            return EXIT_SUCCESS;
        case 'h':
            printf(
"Usage: %s add ...\n"
"       %s del ...\n"
"       %s mod ...\n"
"       %s ls\n"
"GTPU daemon control utility.\n"
"\n"
"  -h   display this help and exit \n"
"  -v   display version information and exit\n"
"\n"
"Add tunnel\n"
"%s add [PROPERTY VALUE] ... dev DEV\n"
"\n"
"Prints ID of the new tunnel on success.\n"
"\n"
"Properties:\n"
"   local        IP | IPv6           GTPU tunnel attributes\n"
"   local-teid   NUMBER\n"
"   remote       IP | IPv6\n"
"   remote-teid  NUMBER\n"
"   type         \"ip\" | \"ipv6\"       inner protocol\n"
"\n"
"DEV specifies the network interface for gtpd to claim. This is\n"
"normally a veth device. ARP should be turned off and the other end's\n"
"MAC address should be set to 00:00:00:00:00:01.\n"
"\n"
"GTPD_SESSION_LEADER_PID environment variable specifies the PID of the\n"
"\"session leader\" (optional). The tunnel is removed automatically\n"
"when the specified process exits.\n"
"\n"
"Delete tunnel\n"
"%s del ID\n"
"\n"
"Modify tunnel\n"
"%s mod ID set [PROPERTY VALUE] ...\n"
"\n"
"See \"add\" command for the list of recognized properties.\n"
"\n"
"List tunnels\n"
"%s ls\n"
"\n"
"GTPD_SOCKET environment variable overrides daemon socket path.\n",
                argv[0], argv[0], argv[0], argv[0],
                argv[0], argv[0], argv[0], argv[0]
            );
            return EXIT_SUCCESS;
        }
    }

    try {
        const char *sock_path = getenv("GTPD_SOCKET");
        if (!sock_path) sock_path = "/run/gtpd";

        auto cmd = parse_args(argv + optind);
        CmdHandler handler(sock_path);

        return std::visit(handler, cmd);

    } catch (const std::exception &e) {
        fprintf(stderr, "%s\n", e.what());
        return EXIT_FAILURE;
    }
}

union Columns {
    int width[0];
    struct {
        int id;
        int local;
        int local_teid;
        int remote;
        int remote_teid;
        int type;
        int halt;
        int encap_ok;
        int encap_drop_rx;
        int encap_drop_tx;
        int decap_ok;
        int decap_drop_rx;
        int decap_drop_tx;
        int decap_bad;
        int decap_trunc;
    };
};

static int fmt_header(std::vector<char> &buf, const Columns &cols) {
    return snprintf(
        &buf[0], buf.size(),
        "%*s  %*s  %*s  %*s  %*s  %*s  %*s  %*s  %*s  %*s  %*s  %*s  "
        "%*s  %*s  %*s\n",
        cols.id, "id",
        cols.local, "local",
        cols.local_teid, "local-teid",
        cols.remote, "remote",
        cols.remote_teid, "remote-teid",
        cols.type, "type",
        cols.halt, "halt",
        cols.encap_ok, "encap-ok",
        cols.encap_drop_rx, "encap-drop-rx",
        cols.encap_drop_tx, "encap-drop-tx",
        cols.decap_ok, "decap-ok",
        cols.decap_drop_rx, "decap-drop-rx",
        cols.decap_drop_tx, "decap-drop-tx",
        cols.decap_bad, "decap-bad",
        cols.decap_trunc, "decap-trunc"
    );
}

static int fmt_row(std::vector<char> &buf, const ApiGtpuTunnelListItemMsg &sess,
                   const Columns &cols) {

    char local[INET6_ADDRSTRLEN], remote[INET6_ADDRSTRLEN];

    char type[8 + 1];
    unsigned inner_proto = ntohs(sess.inner_proto);
    switch (inner_proto) {
    case ETH_P_IP:
        strcpy(type, "ip");
        break;
    case ETH_P_IPV6:
        strcpy(type, "ipv6");
        break;
    default:
        snprintf(type, sizeof(type), "%x", inner_proto);
        break;
    }

    return snprintf(
        &buf[0], buf.size(),
        "%*u  %*s  %*u  %*s  %*u  %*s  %*d  %*lu  %*lu  %*lu  %*lu  "
        "%*lu  %*lu  %*lu  %*lu\n",
        cols.id, sess.id,
        cols.local, inet_ntop(
            sess.tunnel.address_family,
            &sess.tunnel.local,
            local, sizeof(local)
        ),
        cols.local_teid, ntohl(sess.tunnel.local_teid),
        cols.remote, inet_ntop(
            sess.tunnel.address_family,
            &sess.tunnel.remote,
            remote, sizeof(remote)
        ),
        cols.remote_teid, ntohl(sess.tunnel.remote_teid),
        cols.type, type,
        cols.halt, sess.halt,
        cols.encap_ok, sess.encap_ok,
        cols.encap_drop_rx, sess.encap_drop_rx,
        cols.encap_drop_tx, sess.encap_drop_tx,
        cols.decap_ok, sess.decap_ok,
        cols.decap_drop_rx, sess.decap_drop_rx,
        cols.decap_drop_tx, sess.decap_drop_tx,
        cols.decap_bad, sess.decap_bad,
        cols.decap_trunc, sess.decap_trunc
    );
}

// Update column widths.  Assume cells separated by 1 or more whitespace
// characters, no inner whitespace in cells.
static void update_cols(const std::vector<char> &buf, int rc, Columns &cols) {
    int col = 0, start;
    for (int i = 0; i < rc; ++i) {
        if (isspace(buf[i])) {
            if (i && !isspace(buf[i - 1])) {
                cols.width[col] = std::max(cols.width[col], i - start);
                ++col;
            }
        } else {
            if (i == 0 || isspace(buf[i - 1])) start = i;
        }
    }
}

static void print_tunnels(const std::vector<ApiGtpuTunnelListItemMsg> &list) {
    std::vector<char> buf(256);
    Columns cols = {}; cols.id = strlen("# id");
    int rc;
    for (int i = 0; i < 2; ++i) {
        while ((rc = fmt_header(buf, cols)) > 0 && size_t(rc) > buf.size()) {
            buf.resize(rc);
        }
        if (rc > 0) {
            update_cols(buf, rc, cols);
            buf[0] = '#';
            if (i) fwrite(&buf[0], sizeof(char), rc, stdout);
        }
        for (const auto &sess: list) {
            while ((rc = fmt_row(buf, sess, cols)) > 0 && size_t(rc) > buf.size()) {
                buf.resize(rc);
            }
            if (rc > 0) {
                update_cols(buf, rc, cols);
                if (i) fwrite(&buf[0], sizeof(char), rc, stdout);
            }
        }
    }
}

// TODO replace with lubbpf once it becomes widely available.

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2018 Facebook */

#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>

static int libbpf_netlink_open(__u32 *nl_pid)
{
	struct sockaddr_nl sa;
	socklen_t addrlen;
	int one = 1, ret;
	int sock;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0)
		return -errno;

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		ret = -errno;
		goto cleanup;
	}

	addrlen = sizeof(sa);
	if (getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0) {
		ret = -errno;
		goto cleanup;
	}

	if (addrlen != sizeof(sa)) {
		ret = -EINVAL;
		goto cleanup;
	}

	*nl_pid = sa.nl_pid;
	return sock;

cleanup:
	close(sock);
	return ret;
}

static int bpf_netlink_recv(int sock, __u32 nl_pid, int seq)
{
	bool multipart = true;
	struct nlmsgerr *err;
	struct nlmsghdr *nh;
	char buf[4096];
	int len, ret;

	while (multipart) {
		multipart = false;
		len = recv(sock, buf, sizeof(buf), 0);
		if (len < 0) {
			ret = -errno;
			goto done;
		}

		if (len == 0)
			break;

		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_pid != nl_pid) {
				ret = -EINVAL;
				goto done;
			}
			if (nh->nlmsg_seq != seq) {
				ret = -EINVAL;
				goto done;
			}
			if (nh->nlmsg_flags & NLM_F_MULTI)
				multipart = true;
			switch (nh->nlmsg_type) {
			case NLMSG_ERROR:
				err = (struct nlmsgerr *)NLMSG_DATA(nh);
				if (!err->error)
					continue;
				ret = err->error;
				goto done;
			case NLMSG_DONE:
				return 0;
			default:
				break;
			}
		}
	}
	ret = 0;
done:
	return ret;
}

int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
	int sock, seq = 0, ret;
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	__u32 nl_pid;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0)
		return sock;

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;

	/* started nested attribute for XDP */
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | IFLA_XDP;
	nla->nla_len = NLA_HDRLEN;

	/* add XDP fd */
	nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
	nla_xdp->nla_type = IFLA_XDP_FD;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len += nla_xdp->nla_len;

	/* if user passed in any flags, add those too */
	if (flags) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = IFLA_XDP_FLAGS;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
		nla->nla_len += nla_xdp->nla_len;
	}

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		ret = -errno;
		goto cleanup;
	}
	ret = bpf_netlink_recv(sock, nl_pid, seq);

cleanup:
	close(sock);
	return ret;
}
