#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "common_kern.h"


char LICENSE[] SEC("license") = "GPL";


const __u32 blockme = 16843009; // 1.1.1.1 -> int

// map debug event 
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ioc_events SEC(".maps");

// ioc_block
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // IPv4 in network byte order
    __type(value, __u8);   // flag (1 = blocked)
} blocked_ips SEC(".maps");

// static function
static __always_inline void send_ioc_event(enum ioc_event_type type, void *data) {
    struct ioc_event *evt;

    evt = bpf_ringbuf_reserve(&ioc_events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid  = pid_tgid & 0xFFFFFFFF;
    evt->tgid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid & 0xFFFFFFFF;
    evt->gid = uid_gid >> 32;

    evt->type = type;

    // Copy payload 
    if (type == IOC_EVT_EXEC_FILE) {
        const struct exec_payload *p = data;
        bpf_probe_read_kernel_str(evt->exec.file_path, sizeof(evt->exec.file_path), p->file_path);
        evt->exec.inode_id = p->inode_id;
    } else if (type == IOC_EVT_CONNECT_IP) {
        const struct net_payload *p = data;
        evt->net.saddr = p->saddr;
        evt->net.daddr = p->daddr;
        evt->net.sport = p->sport;
        evt->net.dport = p->dport;
    } else if (type == IOC_EVT_CMD_CONTROL) {
        const struct cmd_payload *p = data;
        bpf_probe_read_kernel_str(evt->cmdctl.cmd, sizeof(evt->cmdctl.cmd), p->cmd);
    }

    bpf_ringbuf_submit(evt, 0);
}

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // Satisfying "cannot override a denial" rule
    if (ret != 0)
    {
        return ret;
    }

    // Only IPv4 in this example
    if (address->sa_family != AF_INET)
    {
        return 0;
    }

    // Cast the address to an IPv4 socket address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    // Where do you want to go?
    __u32 dest = addr->sin_addr.s_addr;
    bpf_printk("lsm: found connect to %d", dest);
    if (dest == blockme)
    {
        struct exec_payload exe_test; 
        exe_test.inode_id = 100000;
        bpf_probe_read_kernel_str(exe_test.file_path, sizeof(exe_test.file_path), "test_file_vcs1.txt");
        send_ioc_event(IOC_EVT_EXEC_FILE, &exe_test);
        // bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}