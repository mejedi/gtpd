#pragma once
#include <cstdint>

enum {
    API_RESPONSE_CODE = 0,
    API_CREATE_GTPU_TUNNEL_CODE = 1,
    API_DELETE_GTPU_TUNNEL_CODE = 2,
    API_MODIFY_GTPU_TUNNEL_CODE = 3,
    API_LIST_GTPU_TUNNELS_CODE = 4,
    API_GTPU_TUNNEL_LIST_ITEM_CODE = 5,
};

#define API_MSG_FIELDS(_) \
    uint32_t length; \
    uint32_t code; \

struct ApiResponseMsg {
    API_MSG_FIELDS (API_RESPONSE_CODE)

    int32_t rc; // -errno on failure
};

struct ApiAddr {
    union {
        uint32_t ip;
        uint32_t ip6[4];
    };
};

struct ApiGtpuTunnel {
    uint32_t address_family; // AF_INET (2), AF_INET6 (10)
    ApiAddr local;
    uint32_t local_teid;
    ApiAddr remote;
    uint32_t remote_teid;
};

// Request: ApiCreateGtpuTunnelMsg (+ XDP socket FD in SCM_RIGHTS)
struct ApiCreateGtpuTunnelMsg {
    API_MSG_FIELDS (API_CREATE_GTPU_TUNNEL_CODE)

    ApiGtpuTunnel tunnel;
    uint32_t inner_proto; // htons(ETH_P_IP) (htons(0x0800)),
                          // htons(ETH_P_IPV6) (htons(0x86dd))
    uint32_t cookie;
};
// Response: ApiResponseMsg (+ XDP BPF prog FD in SCM_RIGHTS)

// Request: ApiDeleteGtpuTunnelMsg
struct ApiDeleteGtpuTunnelMsg {
    API_MSG_FIELDS (API_DELETE_GTPU_TUNNEL_CODE)

    uint32_t id;
};
// Response: ApiResponseMsg

// Request: ApiModifyGtpuTunnelMsg
struct ApiModifyGtpuTunnelMsg {
    API_MSG_FIELDS (API_MODIFY_GTPU_TUNNEL_CODE)

    uint32_t id;
    uint32_t flags;
    ApiGtpuTunnel new_tunnel;
    uint32_t new_inner_proto;
};
// Response: ApiResponseMsg

enum {
    API_MODIFY_GTPU_TUNNEL_LOCAL_FLAG = 1,
    API_MODIFY_GTPU_TUNNEL_LOCAL_TEID_FLAG = 2,
    API_MODIFY_GTPU_TUNNEL_REMOTE_FLAG = 4,
    API_MODIFY_GTPU_TUNNEL_REMOTE_TEID_FLAG = 8,
    API_MODIFY_GTPU_TUNNEL_INNER_PROTO_FLAG = 16,
};

// Request: ApiListGtpuTunnelsMsg
struct ApiListGtpuTunnelsMsg {
    API_MSG_FIELDS (API_LIST_GTPU_TUNNELS_CODE)
};
// Response: ApiGtpuTunnelListItemMsg* RpcResponseMsg

struct ApiGtpuTunnelListItemMsg {
    API_MSG_FIELDS (API_GTPU_TUNNEL_LIST_ITEM_CODE)

    uint32_t id;

    ApiGtpuTunnel tunnel;

    uint32_t inner_proto;

    // A malfunctioning or malicious client could clobber the
    // corresponding XDP socket's memory-mapped io interfaces.  When
    // an inconsictency is detected, the tunnel gets halted.
    uint32_t halt;

    uint32_t cookie;

    uint64_t encap_ok;
    uint64_t encap_drop_rx;
    uint64_t encap_drop_tx;

    uint64_t decap_ok;
    uint64_t decap_drop_rx;
    uint64_t decap_drop_tx;
    uint64_t decap_bad;
    uint64_t decap_trunc;
};

union ApiMsg {
    struct {
        API_MSG_FIELDS (_)
#undef API_MSG_FIELDS
    };
    ApiResponseMsg           response;
    ApiCreateGtpuTunnelMsg   create_gtpu_tunnel;
    ApiDeleteGtpuTunnelMsg   delete_gtpu_tunnel;
    ApiModifyGtpuTunnelMsg   modify_gtpu_tunnel;
    ApiListGtpuTunnelsMsg    list_gtpu_tunnels;
    ApiGtpuTunnelListItemMsg gtpu_tunnel_list_item;
};
