#include "cache_line_aligned.h"
#include <unistd.h>

namespace detail{
const size_t cache_line_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
}
