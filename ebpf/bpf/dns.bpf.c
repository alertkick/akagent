// SPDX-License-Identifier: GPL-2.0 OR MIT
// dns.bpf.c - BPF program for monitoring DNS queries
// Security: Tracks DNS lookups via sendto/sendmsg to port 53
// Captures query names for threat detection (C2, DGA, tunneling, exfiltration)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"
#include "discarders.h"
#include "output.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Force BTF export
struct dns_event *unused_dns_event __attribute__((unused));

DECLARE_EVENT_OUTPUT(dns_events, struct dns_event, 256 * 1024);

// Address family constants
#define AF_INET  2
#define AF_INET6 10

// DNS port (network byte order and host byte order)
#define DNS_PORT 53

// sockaddr structures (same as network.bpf.c)
struct dns_sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    __u8 pad[8];
};

struct dns_sockaddr_in6 {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
};

// msghdr layout on x86_64 (using fixed-size types for ABI safety)
struct dns_user_msghdr {
    __u64 msg_name;       // void __user *
    __u32 msg_namelen;
    __u32 _pad;
    __u64 msg_iov;        // struct iovec __user *
    __u64 msg_iovlen;
};

struct dns_iovec {
    __u64 iov_base;       // void __user *
    __u64 iov_len;
};

// Helper to fill common fields
static __always_inline void fill_common_dns(struct dns_event *event) {
    struct task_struct *task;
    u64 pid_tgid, uid_gid;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_DNS_QUERY;

    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = (u32)(pid_tgid >> 32);

    uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
        }
    }
}

// Parse DNS query name from packet buffer using flattened single-loop approach.
// Converts label-encoded DNS name (e.g., 03www06google03com00) to dot-separated
// form (www.google.com). Returns number of bytes written to event->qname.
//
// Uses a state machine: remaining_in_label tracks whether we're reading a label
// length byte (0) or label character bytes (>0). This avoids nested loops
// which the BPF verifier rejects.
static __always_inline __u16 parse_dns_name(struct dns_event *event,
                                             const void *buf, __u64 pkt_len) {
    __u32 out_pos = 0;
    __u32 pos = DNS_HEADER_SIZE;  // Skip 12-byte DNS header
    __u8 remaining_in_label = 0;
    int first_label = 1;

    // Bounded loop: max DNS_MAX_NAME_LEN iterations (128)
    // Each iteration processes one byte from the DNS packet
    for (int i = 0; i < DNS_MAX_NAME_LEN; i++) {
        if (pos >= pkt_len)
            break;

        __u8 b = 0;
        if (bpf_probe_read_user(&b, 1, (const char *)buf + pos) < 0)
            break;

        pos++;

        if (remaining_in_label == 0) {
            // This byte is a label length
            if (b == 0)
                break;  // End of name (null terminator)
            if (b > 63)
                break;  // Compression pointer or invalid label

            remaining_in_label = b;

            // Add dot separator before this label (except for first)
            if (!first_label && out_pos < DNS_MAX_NAME_LEN - 1) {
                event->qname[out_pos & (DNS_MAX_NAME_LEN - 1)] = '.';
                out_pos++;
            }
            first_label = 0;
        } else {
            // This byte is a label character
            if (out_pos < DNS_MAX_NAME_LEN - 1) {
                event->qname[out_pos & (DNS_MAX_NAME_LEN - 1)] = (char)b;
                out_pos++;
            }
            remaining_in_label--;
        }
    }

    // Null-terminate
    if (out_pos < DNS_MAX_NAME_LEN)
        event->qname[out_pos & (DNS_MAX_NAME_LEN - 1)] = 0;

    // Read QTYPE and QCLASS after the name
    __u16 qtype = 0, qclass = 0;
    if (pos + 4 <= pkt_len) {
        bpf_probe_read_user(&qtype, 2, (const char *)buf + pos);
        bpf_probe_read_user(&qclass, 2, (const char *)buf + pos + 2);
        event->qtype = __builtin_bswap16(qtype);
        event->qclass = __builtin_bswap16(qclass);
    }

    return (__u16)out_pos;
}

// Parse DNS header and extract transaction ID.
// Returns 0 on success, -1 on failure.
static __always_inline int parse_dns_header(struct dns_event *event,
                                             const void *buf, __u64 pkt_len) {
    if (pkt_len < DNS_HEADER_SIZE)
        return -1;

    // Read transaction ID (first 2 bytes, network byte order)
    __u16 txn_id = 0;
    if (bpf_probe_read_user(&txn_id, 2, buf) < 0)
        return -1;
    event->id = __builtin_bswap16(txn_id);

    // Read flags (bytes 2-3) to verify this is a query (QR=0)
    __u16 flags = 0;
    if (bpf_probe_read_user(&flags, 2, (const char *)buf + 2) < 0)
        return -1;
    flags = __builtin_bswap16(flags);

    // QR bit is the highest bit of flags. QR=0 means query, QR=1 means response.
    // We only capture queries (outgoing).
    if (flags & 0x8000)
        return -1;  // This is a response, not a query

    return 0;
}

// Fill destination address from sockaddr into the event
static __always_inline void fill_dns_addr(struct dns_event *event,
                                           const void *addr) {
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), addr);
    event->family = family;

    if (family == AF_INET) {
        struct dns_sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), addr);
        event->dport = __builtin_bswap16(sa.sin_port);
        __builtin_memcpy(event->daddr, &sa.sin_addr, 4);
    } else if (family == AF_INET6) {
        struct dns_sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), addr);
        event->dport = __builtin_bswap16(sa6.sin6_port);
        __builtin_memcpy(event->daddr, sa6.sin6_addr, 16);
    }
}

// Check if sockaddr destination port is DNS (port 53).
// Returns 1 if DNS, 0 otherwise.
static __always_inline int is_dns_dest(const void *addr) {
    if (!addr)
        return 0;

    // Read first 4 bytes: family (2) + port (2)
    __u16 family = 0;
    __u16 port = 0;
    bpf_probe_read_user(&family, sizeof(family), addr);
    bpf_probe_read_user(&port, sizeof(port), (const char *)addr + 2);

    if (family != AF_INET && family != AF_INET6)
        return 0;

    return (__builtin_bswap16(port) == DNS_PORT);
}

// =============================================================================
// Tracepoint: sys_enter_sendto
// =============================================================================
// sendto(int fd, const void *buf, size_t len, int flags,
//        const struct sockaddr *dest_addr, socklen_t addrlen)
// args: [0]=fd, [1]=buf, [2]=len, [3]=flags, [4]=dest_addr, [5]=addrlen

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    const void *dest_addr = (const void *)ctx->args[4];

    // Fast path: skip if no destination address (connected socket - can't determine port)
    if (!dest_addr)
        return 0;

    // Fast path: check if destination is port 53 before any expensive operations
    if (!is_dns_dest(dest_addr))
        return 0;

    const void *buf = (const void *)ctx->args[1];
    __u64 len = ctx->args[2];

    // DNS packet must be at least header size
    if (len < DNS_HEADER_SIZE)
        return 0;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NETWORK, tgid, comm))
        return 0;

    struct dns_event *event = EVENT_OUTPUT_BEGIN(dns_events, struct dns_event);
    if (!event)
        return 0;

    fill_common_dns(event);
    fill_dns_addr(event, dest_addr);

    // Parse DNS header (verify it's a query)
    if (parse_dns_header(event, buf, len) < 0) {
        EVENT_OUTPUT_DISCARD(dns_events, event);
        return 0;
    }

    // Parse DNS query name
    event->name_len = parse_dns_name(event, buf, len);

    EVENT_OUTPUT_END(dns_events, event, struct dns_event, ctx);
    return 0;
}

// =============================================================================
// Tracepoint: sys_enter_sendmsg
// =============================================================================
// sendmsg(int sockfd, const struct msghdr *msg, int flags)
// args: [0]=fd, [1]=msg, [2]=flags

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls__sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    // Read the msghdr from userspace
    struct dns_user_msghdr mhdr = {};
    if (bpf_probe_read_user(&mhdr, sizeof(mhdr), (void *)ctx->args[1]) < 0)
        return 0;

    // Must have a destination address to check port
    if (!mhdr.msg_name || mhdr.msg_namelen < 4)
        return 0;

    // Fast path: check if destination is port 53
    if (!is_dns_dest((const void *)mhdr.msg_name))
        return 0;

    // Must have at least one iovec with data
    if (!mhdr.msg_iov || mhdr.msg_iovlen < 1)
        return 0;

    // Read first iovec to get the data buffer
    struct dns_iovec iov = {};
    if (bpf_probe_read_user(&iov, sizeof(iov), (void *)mhdr.msg_iov) < 0)
        return 0;

    if (!iov.iov_base || iov.iov_len < DNS_HEADER_SIZE)
        return 0;

    // In-kernel discard check
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (should_discard(DISCARD_CAT_NETWORK, tgid, comm))
        return 0;

    struct dns_event *event = EVENT_OUTPUT_BEGIN(dns_events, struct dns_event);
    if (!event)
        return 0;

    fill_common_dns(event);
    fill_dns_addr(event, (const void *)mhdr.msg_name);

    // Parse DNS header (verify it's a query)
    if (parse_dns_header(event, (const void *)iov.iov_base, iov.iov_len) < 0) {
        EVENT_OUTPUT_DISCARD(dns_events, event);
        return 0;
    }

    // Parse DNS query name
    event->name_len = parse_dns_name(event, (const void *)iov.iov_base, iov.iov_len);

    EVENT_OUTPUT_END(dns_events, event, struct dns_event, ctx);
    return 0;
}
