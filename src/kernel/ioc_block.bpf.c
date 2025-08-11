#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "common_kern.h"


char LICENSE[] SEC("license") = "GPL";


const __u32 blockme = 16843009; // 1.1.1.1 -> int

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
        send_debug_log(BLOCKED_ACTION, "[kernel space socket_connect] block connection");
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}