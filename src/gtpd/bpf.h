#pragma once
#include "common/fd.h"
#include <linux/bpf.h>
#include <cstdint>

Fd bpf_create_map(enum bpf_map_type map_type,
                  unsigned key_size,
                  unsigned value_size,
                  unsigned max_entries,
                  unsigned map_flags,
                  const Fd &inner_map_fd = Fd());

void bpf_update_elem(const Fd& fd,
                     const void *key, const void *value, uint64_t flags);

void bpf_delete_elem(const Fd& fd, const void *key);

Fd bpf_prog_load(bpf_prog_type type,
                 const bpf_insn *insns, int insn_cnt,
                 const char *license);

// Unused BPF opcode repurposed as a literal label.
//
// Writing BPF bytecode by hand is mostly ok, but computing and updating
// relative offsets for jumps is the major PITA.  Use labels for
// convenience and convert to standard BPF with a postprocessing pass.
#define BPF_LABEL_ 0xf0
#define BPF_LABEL(L) \
    ((struct bpf_insn) { .code = BPF_LABEL_, .dst_reg = 0, .src_reg = 0, .off = L, .imm = 0 })

// Resolve literal labels in prog and convert to standard BPF.  Return
// the resulting program length.  Literal label values are used as
// indices into labels array; must be large enough.
int bpf_resolve_labels(bpf_insn *prog, int in_count, int *labels);
