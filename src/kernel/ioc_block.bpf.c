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
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1024);
//     __type(key, __u32);    // IPv4 in network byte order
//     __type(value, __u8);   // flag (1 = blocked)
// } blocked_ips SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __type(key, struct ip_lpm_key);
//     __type(value, enum ip_status);
//     __uint(max_entries, LIMIT_IP_CACHE);
// } block_list_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LIMIT_IP_CACHE);
    __type(key, struct ip_lpm_key);
    __type(value, enum ip_status);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} block_list_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, LIMIT_IP_STORE);
    __type(key, struct ip_lpm_key);
    __type(value, enum ip_status);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ioc_ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5);
    __type(key, uint32_t);
    __type(value, uint32_t);
} filelesslock_args_map SEC(".maps");
// static function
static __always_inline void send_ioc_event(enum ioc_event_type type, void *data) {
    struct ioc_event *evt;

    evt = bpf_ringbuf_reserve(&ioc_events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }

    __builtin_memset(evt, 0, sizeof(*evt));
    evt->timestamp_ns = bpf_ktime_get_ns();

    // __u64 pid_tgid = bpf_get_current_pid_tgid();
    // evt->pid  = pid_tgid & 0xFFFFFFFF;
    // evt->tgid = pid_tgid >> 32;

    // __u64 uid_gid = bpf_get_current_uid_gid();
    // evt->uid = uid_gid & 0xFFFFFFFF;
    // evt->gid = uid_gid >> 32;

    evt->type = type;

    // Copy payload 
    if (type == IOC_EVT_EXEC_FILE) {
        const struct exec_payload *p = data;
        bpf_probe_read_kernel_str(evt->exec.file_path, sizeof(evt->exec.file_path), p->file_path);
        evt->exec.inode_id = p->inode_id;
    } else if (type == IOC_EVT_CONNECT_IP) {
        const struct net_payload *p = data;
        evt->net.family   = p->family;
        evt->net.daddr_v4 = p->daddr_v4;
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
        }
        evt->net.dport    = p->dport;
        evt->net.protocol = p->protocol;
        // if(p->family == AF_INET6) {
        //     bpf_printk("1234567834567 IPV6\n");
        // }
    } else if (type == IOC_EVT_CMD_CONTROL) {
        const struct cmd_payload *p = data;
        bpf_probe_read_kernel_str(evt->cmd.cmd, sizeof(evt->cmd.cmd), p->cmd);
    } else if(type == IOC_EVT_MOUNT_EVENT) {
        const struct mount_payload *p = data;
        evt->mnt.action = p->action;
        bpf_probe_read_kernel_str(evt->mnt.dev_name, sizeof(evt->mnt.dev_name), p->dev_name);
        bpf_probe_read_kernel_str(evt->mnt.fs_type, sizeof(evt->mnt.fs_type), p->fs_type);
        bpf_probe_read_kernel_str(evt->mnt.mnt_point, sizeof(evt->mnt.mnt_point), p->mnt_point);
        // __builtin_memcpy(evt->mnt.mnt_point, p->mnt_point, sizeof(p->mnt_point));
        // bpf_printk("debug mount event: %s\n", p->mnt_point);
        // bpf_printk("debug mount event second: %s\n", evt->mnt.mnt_point);
    }
    else if(type == IOC_EVT_FILE_CHANGE) {
        const struct file_change_payload *p = data;
        bpf_probe_read_kernel_str(evt->file_change.file_name, sizeof(evt->file_change.file_name), p->file_name);
        evt->file_change.inode_id = p->inode_id;
        evt->file_change.file_change_type = p->file_change_type;
    }
    bpf_ringbuf_submit(evt, 0);
}

// SEC("lsm/socket_connect")
// int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
// {
//     // Satisfying "cannot override a denial" rule
//     if (ret != 0)
//     {
//         return ret;
//     }
//     struct sock *sk = sock->sk;
//     if (!sk) {
//         return 0;
//     }
//     int return_value = 0;
//     struct ip_key key = {};
//     struct net_payload evt = {};
//     evt.family = address->sa_family;
//     evt.status = ALLOW;
//     bpf_probe_read_kernel(&evt.protocol, sizeof(sk->sk_protocol), &sk->sk_protocol);

//     key.family = address->sa_family;
//     if (address->sa_family == AF_INET) {
//         struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
//         evt.daddr_v4 = addr4->sin_addr.s_addr;
//         evt.dport    = addr4->sin_port;

//         key.ipv4 = evt.daddr_v4;
//     }
//     else if (address->sa_family == AF_INET6) {
//         struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
//         bpf_probe_read_kernel(&evt.daddr_v6, sizeof(evt.daddr_v6), &addr6->sin6_addr);
//         evt.dport    = addr6->sin6_port;

//         bpf_probe_read_kernel(&key.ipv6, sizeof(key.ipv6), &addr6->sin6_addr);
//     }
//     else {
//         return 0;
//     }
//     send_ioc_event(IOC_EVT_CONNECT_IP, &evt);

//     // example prevention IPV4
//     // if (evt.daddr_v4 == blockme) {
//     //     return -EPERM;
//     // }

//     return return_value;
// }

// SEC("xdp")
// int xdp_pass(struct xdp_md *ctx)
// {
//     struct ip_key key = {};
//     struct net_payload np = {};
//     np.status = ALLOW;
//     if (!parse_l3l4(ctx, &key, &np)) {
//         return XDP_PASS;
//     }
//     if (np.family == AF_INET) {
//         send_ioc_event(IOC_EVT_CONNECT_IP, &np);
//     } 
//     else if (np.family == AF_INET6) {
//         send_ioc_event(IOC_EVT_CONNECT_IP, &np);
//     }
//     return XDP_PASS;
// }

SEC("xdp")
int xdp_ioc_block(struct xdp_md *ctx)
{
    struct net_payload np = {};
    np.status = ALLOW;
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    struct ip_lpm_key lpm_key = {};
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip4 = (void *)(eth + 1);
        if ((void *)(ip4 + 1) > data_end) return XDP_PASS;
        lpm_key.prefixlen = 32;
        __u32 ip_be = ip4->saddr; 
        __builtin_memcpy(lpm_key.data, &ip_be, 4);  
        np.family   = AF_INET;
        np.daddr_v4 = ip4->saddr;
        np.protocol = ip4->protocol;

        void *l4 = (void *)ip4 + ip4->ihl*4;
        if (l4 <= data_end) {
            if (ip4->protocol == IPPROTO_TCP) {
                struct tcphdr *th = l4;
                if ((void *)(th + 1) <= data_end)
                    np.dport = th->dest;
            } else if (ip4->protocol == IPPROTO_UDP) {
                struct udphdr *uh = l4;
                if ((void *)(uh + 1) <= data_end)
                    np.dport = uh->dest;
            }
        }
    }
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;
        lpm_key.prefixlen = 128;
        __builtin_memcpy(lpm_key.data, &ip6->saddr, 16);
        np.family   = AF_INET6;
        __builtin_memcpy(np.daddr_v6, &ip6->saddr, 16);
        np.protocol = ip6->nexthdr;
        void *l4 = (void *)(ip6 + 1);
        if (l4 <= data_end) {
            if (ip6->nexthdr == IPPROTO_TCP) {
                struct tcphdr *th = l4;
                if ((void *)(th + 1) <= data_end)
                    np.dport = th->dest;
            } else if (ip6->nexthdr == IPPROTO_UDP) {
                struct udphdr *uh = l4;
                if ((void *)(uh + 1) <= data_end)
                    np.dport = uh->dest;
            }
        }
    } 
    else {
        return XDP_PASS; // non-IP
    }
    enum ip_status *ip_pass = bpf_map_lookup_elem(&block_list_ip, &lpm_key);
    if (ip_pass) {
        if ((*ip_pass) == ALLOW) {
            return XDP_PASS;
        }
    }
    // lookup IOC map
    enum ip_status *verdict = bpf_map_lookup_elem(&ioc_ip_map, &lpm_key);
    if (verdict) {
        np.status = *verdict;
    }
    // drop if DENY
    if (np.status == DENY) {
        send_ioc_event(IOC_EVT_CONNECT_IP, &np);
        return XDP_DROP;
    }
    else {
        // bpf_printk("insert new ip\n");
        bpf_map_update_elem(&block_list_ip, &lpm_key, &np.status, BPF_ANY);
    }
    return XDP_PASS;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int on_sys_enter_mount(struct trace_event_raw_sys_enter *ctx)
{
    struct mount_payload evt;
    __u64 dev_name_ptr = ctx->args[0]; // const char *dev_name
    __u64 dir_name_ptr = ctx->args[1]; // const char *dir_name
    __u64 type_ptr     = ctx->args[2]; // const char *type

    evt.action = MOUNT_ADD;
    bpf_probe_read_user_str(evt.dev_name, sizeof(evt.dev_name), (void *)dev_name_ptr);
    bpf_probe_read_user_str(evt.fs_type,  sizeof(evt.fs_type),  (void *)type_ptr);
    bpf_probe_read_user_str(evt.mnt_point,sizeof(evt.mnt_point),(void *)dir_name_ptr);

    // bpf_printk("this is eBPF: %s\n", evt.mnt_point);
    send_ioc_event(IOC_EVT_MOUNT_EVENT, &evt);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_umount")
int on_sys_enter_umount(struct trace_event_raw_sys_enter *ctx)
{
    struct mount_payload evt;

    __u64 dir_name_ptr = ctx->args[0]; 

    evt.action = MOUNT_REMOVE;

    bpf_probe_read_user_str(evt.mnt_point,sizeof(evt.mnt_point),(void *)dir_name_ptr);
    // bpf_printk("that are eBPF: %s\n", evt.mnt_point);
    send_ioc_event(IOC_EVT_MOUNT_EVENT, &evt);

    return 0;
}
SEC("lsm/bprm_creds_from_file") 
int BPF_PROG(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file, int ret) {

    uint32_t *val, blocked = 0, reason = 0, zero = 0;
    uint32_t k = FILELESS_PROFILE_KEY;
    unsigned int links;
    // struct process_event *event;
    struct task_struct *task;
    struct file *f;
    const unsigned char *p;

    if (ret != 0 ) {
        return ret;
    }

    links = BPF_CORE_READ(file, f_path.dentry, d_inode, __i_nlink);
    if (links > 0) {
        return ret;
    }
    bpf_printk("have file exe debug\n");
    val = bpf_map_lookup_elem(&filelesslock_args_map, &k);
    if (!val) {
        return ret;
    }
    blocked = *val;
    if (blocked == FILELESS_ALLOW) {
        return ret;
    }
    else if(blocked == FILELESS_RESTRICTED) {
        return -EPERM;
    }
    else if (blocked == FILELESS_BASELINE) {
        return ret;
    }
    return 0;
}
SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct pt_regs *ctx)
{
    bpf_printk("vfs_write debug\n");
    return 0;
}

