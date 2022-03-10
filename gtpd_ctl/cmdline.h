#pragma once
#include "gtpd/api.h"
#include <utility>

// Assumes argv pointer array is nullptr-terminated.
std::pair<ApiMsg, const char*> parse_args(const char * const *argv);
