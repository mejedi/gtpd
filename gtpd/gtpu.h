#pragma once
#include <cstdint>
#include <cstddef>

struct GtpuHeader {
    uint8_t ver_flags;
    uint8_t type;
    uint16_t length;
    uint32_t teid;
    uint16_t sequence;
    uint8_t pdu_number;
    uint8_t next_ext_type;
};

constexpr size_t GTPU_FIXED_SIZE = offsetof(GtpuHeader, sequence);
constexpr uint16_t GTPU_PORT = 2152;
constexpr uint8_t GTPU_V1_VER = 1 << 5;
constexpr uint8_t GTPU_VER_MASK = 7 << 5;
constexpr uint8_t GTPU_E_S_PN_BIT = 7;
constexpr uint8_t GTPU_E_BIT = 1 << 2;
constexpr uint8_t GTPU_PT_BIT = 1 << 4;
constexpr uint8_t GTPU_TYPE_GPDU = 255;
