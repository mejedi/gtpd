#include "gtpd.h"
#include "gtpu_pipe.h"
#include "common/version.h"
#include <getopt.h>
#include <systemd/sd-daemon.h>

int main(int argc, char **argv, char **envp) {
    Gtpd::Options opts;

    // Process options.
    int opt;
    while ((opt = getopt(argc, argv, "hv")) != -1) {
        switch (opt) {
        default:
            return EXIT_FAILURE;
        case 'v':
            printf("gtpd %s\n", version);
            return EXIT_SUCCESS;
        case 'h':
            printf(
"Usage: %s [OPTIONS] [PATH]\n"
"GTPU daemon main executable.\n"
"\n"
"Optional PATH specifies the path to bind API socket to. If omitted,\n"
"uses a preconfigured socket passed via systemd socket activation.\n"
"\n"
"  -h   display this help and exit \n"
"  -v   display version information and exit\n"
"\n"
"The daemon reads various parameters from the environment.\n"
"See /etc/gtpd.conf for the up to date documentation.\n",
                argv[0]
            );
            return EXIT_SUCCESS;
        }
    }

    // Process arguments.
    if (argc == optind) {
        // Get descriptor via systemd socket activation.
        int nfds = sd_listen_fds(/* unset env: */ 1);
        if (nfds != 1) {
            fprintf(stderr, "fatal: systemd activation: "
                    "got %d descriptor(s), expecting 1\n", nfds);
            return EXIT_FAILURE;
        }
        int rc = sd_is_socket(SD_LISTEN_FDS_START, AF_UNIX,
                                SOCK_STREAM, /* listen: */ 1);
        if (rc == 0) {
            fputs("fatal: systemd activation: "
                  "wrong socket kind passed, "
                  "expecting a listening UNIX stream socket\n", stderr);
            return EXIT_FAILURE;
        }
        if (rc < 0) {
            fprintf(stderr, "fatal: systemd activation: "
                    "failed to determine socket kind: %s\n",
                    strerror(-rc));
            return EXIT_FAILURE;
        }
        opts.api_sock_fd = SD_LISTEN_FDS_START;
    } else if (argc == optind + 1) {
        opts.api_sock_path = argv[optind];
    } else {
        fputs("fatal: too many arguments\n", stderr);
        return EXIT_FAILURE;
    }

    // Scan environment variables, process GTPD_*.
    for (char **p = envp; *p; ++p) {
        std::string_view s(*p);
        if (s.substr(0, 5) != "GTPD_") continue;
        size_t pos = s.find('=');
        std::string_view key = s.substr(0, pos), val;
        if (pos != s.npos) {
            val = s.substr(pos + 1);
        }
        char *suffix;
        unsigned long lval = (errno = 0, strtoul(val.data(), &suffix, 10));
        if (errno || *suffix || suffix == val.data() || lval > std::numeric_limits<int>::max()) {
            fprintf(stderr, "fatal: parsing option '%s': integer value expected\n", *p);
            return EXIT_FAILURE;
        }
        int ival = int(lval);
        if (key == "GTPD_ENABLE_IP")
            opts.enable_ip = ival;
        else if (key == "GTPD_ENABLE_IPV6")
            opts.enable_ip6 = ival;
        else if (key == "GTPD_WORKERS")
            opts.nworkers = std::max(1, ival);
        else if (key == "GTPD_ENCAP_MTU")
            opts.encap_mtu = std::max(96, ival);
        else if (key == "GTPD_BATCH_SIZE")
            opts.batch_size = std::max(1, ival);
        else if (key == "GTPD_XDP_POOL_SIZE")
            opts.xdp_pool_size = std::max(2, ival);
        else if (key == "GTPD_TUN_DISPATCHER_INITIAL_CAPACITY")
            GtpuTunnelDispatcher::initial_capacity = std::max(2, ival);
        else {
            fprintf(stderr, "fatal: unknown option: %.*s\n", int(key.size()), key.data());
            return EXIT_FAILURE;
        }
    }

    opts.interrupt_sig = SIGUSR1;
    sigaddset(&opts.stop_sig, SIGTERM);
    sigaddset(&opts.stop_sig, SIGINT);

    signal(SIGUSR1, [](int){});
    sigprocmask(SIG_BLOCK, &opts.stop_sig, nullptr);

    try {
        Gtpd gtpd(opts);

        // dry run: ensure that XDP program loads successfully
        GtpuPipe::check_xdp_bpf_prog_can_load();

        gtpd.run();

    } catch (const std::exception &e) {
        fprintf(stderr, "fatal: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
