#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct super_block {
    unsigned int s_dev;
} __attribute__((preserve_access_index));

struct inode {
    unsigned long i_ino;
    struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct file {
    unsigned int f_mode;
    struct inode *f_inode;
} __attribute__((preserve_access_index));

struct dentry {
    struct inode *d_inode;
} __attribute__((preserve_access_index));

#define EPERM 1
#define MAY_WRITE 2
#define FMODE_WRITE 2

struct sentinel_config {
    __u64 inode;
    __u64 device;
    __u32 authorized_tgid;
    __u32 enforce;
    __u64 pidns_device;
    __u64 pidns_inode;
};

struct sentinel_event {
    __u64 time_ns;
    __u64 inode;
    __u64 device;
    __u32 tgid;
    __u32 uid;
    __u32 operation;
    __s32 decision;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sentinel_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int protect_inode(struct inode *inode, __u32 operation)
{
    __u32 zero = 0;
    struct sentinel_config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (!cfg || !cfg->enforce || !inode)
        return 0;

    __u64 ino = BPF_CORE_READ(inode, i_ino);
    __u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    if (ino != cfg->inode)
        return 0;
    if (dev != cfg->device)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    struct bpf_pidns_info namespace_ids = {};
    if (cfg->pidns_inode &&
        bpf_get_ns_current_pid_tgid(cfg->pidns_device, cfg->pidns_inode,
                                    &namespace_ids,
                                    sizeof(namespace_ids)) == 0)
        tgid = namespace_ids.tgid;
    bool authorized = cfg->authorized_tgid != 0 &&
                      cfg->authorized_tgid == tgid;
    __s32 decision = authorized ? 0 : -EPERM;
    __u32 counter_key = authorized ? 1 : 0;
    __u64 *count = bpf_map_lookup_elem(&counters, &counter_key);
    if (count)
        __sync_fetch_and_add(count, 1);

    struct sentinel_event *event =
        bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->time_ns = bpf_ktime_get_ns();
        event->inode = ino;
        event->device = dev;
        event->tgid = tgid;
        event->uid = (__u32)bpf_get_current_uid_gid();
        event->operation = operation;
        event->decision = decision;
        bpf_ringbuf_submit(event, 0);
    }
    return decision;
}

SEC("lsm/file_open")
int BPF_PROG(sentinel_file_open, struct file *file, int ret)
{
    if (ret)
        return ret;
    unsigned int mode = BPF_CORE_READ(file, f_mode);
    if (!(mode & FMODE_WRITE))
        return 0;
    return protect_inode(BPF_CORE_READ(file, f_inode), 1);
}

SEC("lsm/file_permission")
int BPF_PROG(sentinel_file_permission, struct file *file, int mask, int ret)
{
    if (ret)
        return ret;
    if (!(mask & MAY_WRITE))
        return 0;
    return protect_inode(BPF_CORE_READ(file, f_inode), 2);
}

SEC("lsm/inode_unlink")
int BPF_PROG(sentinel_inode_unlink, struct inode *dir,
             struct dentry *dentry, int ret)
{
    (void)dir;
    if (ret)
        return ret;
    return protect_inode(BPF_CORE_READ(dentry, d_inode), 3);
}

SEC("lsm/inode_rename")
int BPF_PROG(sentinel_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry, int ret)
{
    (void)old_dir;
    (void)new_dir;
    if (ret)
        return ret;
    int decision = protect_inode(BPF_CORE_READ(old_dentry, d_inode), 4);
    if (decision)
        return decision;
    return protect_inode(BPF_CORE_READ(new_dentry, d_inode), 4);
}

char LICENSE[] SEC("license") = "GPL";
