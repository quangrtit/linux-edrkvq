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
        evt->net.family   = p->family;
        evt->net.daddr_v4 = p->daddr_v4;
        if (p->family == AF_INET6) {
            __builtin_memcpy(evt->net.daddr_v6, p->daddr_v6, sizeof(p->daddr_v6));
        } else {
            __builtin_memset(evt->net.daddr_v6, 0, sizeof(evt->net.daddr_v6));
        }
        evt->net.dport    = p->dport;
        evt->net.pid      = p->pid;
        evt->net.protocol = p->protocol;
        // bpf_printk("[kernel] ip: %d and port: %d", evt->net.saddr, evt->net.sport);
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
//     int return_value = 0;

//     struct net_payload evt = {};
//     evt.family = address->sa_family;
//     evt.pid = bpf_get_current_pid_tgid() >> 32;

//     if (address->sa_family == AF_INET) {
//         struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
//         evt.daddr_v4 = addr4->sin_addr.s_addr;
//         evt.dport    = addr4->sin_port;
//     }
//     else if (address->sa_family == AF_INET6) {
//         struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
//         bpf_probe_read_kernel(&evt.daddr_v6, sizeof(evt.daddr_v6), &addr6->sin6_addr);
//         evt.dport    = addr6->sin6_port;
//     }
//     else {
//         return 0;
//     }
//     send_ioc_event(IOC_EVT_CONNECT_IP, &evt);

//     // example prevention IPV4
//     if (evt.daddr_v4 == blockme) {
//         return -EPERM;
//     }

//     return return_value;
// }

SEC("lsm/socket_accept")
int BPF_PROG(restrict_accept, struct socket *sock, struct socket *newsock)
{
    bpf_printk("fuck connection\n");
    struct sock *sk = NULL;
    bpf_core_read(&sk, sizeof(sk), &newsock->sk);
    if (!sk)
        return 0;

    struct net_payload evt = {};
    __u16 family = 0, proto = 0;

    // family & protocol
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    evt.family = (__u8)family;
    bpf_core_read(&proto, sizeof(proto), &sk->sk_protocol);
    evt.protocol = proto;

    evt.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (family == AF_INET) {
        __u32 daddr = 0;
        __be16 dport = 0;
        // remote (client)
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
        bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

        evt.daddr_v4 = daddr;   // network order
        evt.dport    = dport;   // network order

    } else if (family == AF_INET6) {
        __be16 dport6 = 0;
        struct in6_addr v6 = {};
        bpf_core_read(&v6, sizeof(v6), &sk->__sk_common.skc_v6_daddr);
        bpf_core_read(&dport6, sizeof(dport6), &sk->__sk_common.skc_dport);

        __builtin_memcpy(evt.daddr_v6, &v6, sizeof(evt.daddr_v6));
        evt.dport = dport6;    
    } else {
        return 0;
    }
    bpf_printk("error connection\n");
    send_ioc_event(IOC_EVT_CONNECT_IP, &evt);


    return 0; 
}
// SEC("lsm/sb_mount") 
// int BPF_PROG(on_sb_mount, const char *dev_name, struct path *path,
//              const char *type, unsigned long flags, void *data)
// {
//     struct mount_payload evt = {};

//     evt.action = MOUNT_ADD;

//     bpf_probe_read_kernel_str(evt.dev_name, sizeof(evt.dev_name), dev_name);

//     bpf_probe_read_kernel_str(evt.fs_type, sizeof(evt.fs_type), type);

//     long len = bpf_d_path(path, evt.mnt_point, sizeof(evt.mnt_point));

//     send_ioc_event(IOC_EVT_MOUNT_EVENT, &evt);
//     return 0;
// }

// SEC("lsm/sb_unmount")
// int BPF_PROG(on_sb_unmount,  struct vfsmount *mnt, int flags) {
//     struct mount_payload evt = {};

//     evt.action = MOUNT_REMOVE;
//     bpf_probe_read_kernel_str(evt.fs_type, sizeof(evt.fs_type),
//                               BPF_CORE_READ(mnt, mnt_sb, s_type, name));

//     send_ioc_event(IOC_EVT_MOUNT_EVENT, &evt);
    
//     return 0;
// }
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
    bpf_printk("that are eBPF: %s\n", evt.mnt_point);
    send_ioc_event(IOC_EVT_MOUNT_EVENT, &evt);

    return 0;
}