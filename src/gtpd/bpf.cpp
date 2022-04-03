#include "bpf.h"

#include <system_error>
#include <sys/syscall.h>

// Wrapper for BPF syscall (not in glibc).
static int bpf(int cmd, bpf_attr *attr, unsigned int size)
{
    return syscall(SYS_bpf, cmd, attr, size);
}

Fd bpf_create_map(enum bpf_map_type map_type,
                  unsigned key_size,
                  unsigned value_size,
                  unsigned max_entries,
                  unsigned map_flags,
                  const Fd &inner_map_fd)
{
    bpf_attr attr = {};
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;
    attr.inner_map_fd = inner_map_fd.get();

    int fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

    if (fd == -1)
        throw std::system_error(errno, std::generic_category(),
                                "Create BPF map");

    return Fd(fd);
}

void bpf_update_elem(const Fd& fd,
                     const void *key, const void *value, uint64_t flags)
{
    bpf_attr attr = {};
    attr.map_fd = fd.get();
    attr.key = reinterpret_cast<uint64_t>(key);
    attr.value = reinterpret_cast<uint64_t>(value);
    attr.flags = flags;

    if (bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) != 0)
        throw std::system_error(errno, std::generic_category(),
                                "Update BPF map");
}

void bpf_delete_elem(const Fd& fd, const void *key) {
    bpf_attr attr = {};
    attr.map_fd = fd.get();
    attr.key = reinterpret_cast<uint64_t>(key);

    if (bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr)))
        throw std::system_error(errno, std::generic_category(),
                                "Update BPF map");
}

Fd bpf_prog_load(bpf_prog_type type,
                 const bpf_insn *insns, int insn_cnt,
                 const char *license)
{
    static const char err_prefix[] = "Loading BPF program: ";
    enum { ERR_PREFIX_LEN = sizeof(err_prefix) - 1 };
    char log_buf[4096];

    bpf_attr attr = {};
    attr.prog_type = type;
    attr.insns = reinterpret_cast<uint64_t>(insns);
    attr.insn_cnt = insn_cnt;
    attr.license = reinterpret_cast<uint64_t>(license);
    attr.log_buf = reinterpret_cast<uint64_t>(log_buf + ERR_PREFIX_LEN );
    attr.log_size = sizeof(log_buf) - ERR_PREFIX_LEN;
    attr.log_level = 1;

    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));

    if (fd >= 0) return Fd(fd);

    memcpy(log_buf, err_prefix, ERR_PREFIX_LEN);
    if (!log_buf[ERR_PREFIX_LEN]) log_buf[ERR_PREFIX_LEN - 2] = 0;

    throw std::system_error(errno, std::generic_category(),
                            log_buf);
}

int bpf_resolve_labels(bpf_insn *prog, int in_count, int *labels)
{
    int out_count = 0;
    // remove BPF_LABEL()-s, record label positionss
    for (int i = 0; i < in_count; ++i) {
        if (prog[i].code == BPF_LABEL_)
            labels[prog[i].off] = out_count;
        else
            prog[out_count++] = prog[i];
    }
    // resolve jump destinations
    for (int i = 0; i < out_count; ++i) {
        switch (BPF_CLASS(prog[i].code)) {
        case BPF_JMP: case BPF_JMP32:
            switch (BPF_OP(prog[i].code)) {
            case BPF_JA: case BPF_JEQ: case BPF_JGT: case BPF_JGE:
            case BPF_JSET: case BPF_JNE: case BPF_JLT: case BPF_JLE:
            case BPF_JSGT: case BPF_JSGE: case BPF_JSLT: case BPF_JSLE:
               prog[i].off = labels[prog[i].off] - i - 1;
            }
        }
    }
    return out_count;
}
