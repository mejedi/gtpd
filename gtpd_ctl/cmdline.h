#pragma once
#include "gtpd/api.h"
#include <utility>
#include <variant>

struct CreateGtpuTunnelCmd {
    ApiCreateGtpuTunnelMsg msg;
    const char *if_name;
    int session_leader_pid = -1;
};

struct DeleteGtpuTunnelCmd {
    ApiDeleteGtpuTunnelMsg msg;
};

struct ModifyGtpuTunnelCmd {
    ApiModifyGtpuTunnelMsg msg;
};

struct ListGtpuTunnelsCmd {
    ApiListGtpuTunnelsMsg msg;
};

using Cmd = std::variant<
    CreateGtpuTunnelCmd,
    DeleteGtpuTunnelCmd,
    ModifyGtpuTunnelCmd,
    ListGtpuTunnelsCmd
>;

// Assumes argv pointer array is nullptr-terminated.
Cmd parse_args(const char * const *argv);
