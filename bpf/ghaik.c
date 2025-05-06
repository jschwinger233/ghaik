// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "if_ether_defs.h"
#include "headers/bpf_endian.h"

#define MAX_ARG_LEN 128
#define TASK_COMM_LEN 16
#define IFNAMSIZ 16


struct pinfo_search {
	char *argv;
	u8 idx_comm;
};

struct pinfo {
	__u32 pid;
	char pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct pinfo);
	__uint(max_entries, 65535);
} cookie_pinfo_map SEC(".maps");

union addr {
	u32 v4addr;
	struct {
		u64 d1;
		u64 d2;
	} v6addr;
} __attribute__((packed));

struct meta {
	u64 pc;
	u64 skb;
	u64 second_param;
	u32 mark;
	u32 netns;
	u32 ifindex;
	u32 pid;
	unsigned char ifname[IFNAMSIZ];
} __attribute__((packed));

struct tuple {
	union addr saddr;
	union addr daddr;
	u16 sport;
	u16 dport;
	u16 l3_proto;
	u8 l4_proto;
	u8 tcp_flags;
	u16 payload_len;
} __attribute__((packed));

struct event {
	struct meta meta;
	struct tuple tuple;
} __attribute__((packed));

const struct event *_ __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} events SEC(".maps");

static int __noinline find_last_slash_in_arg0(__u32 index, void *data)
{
	struct pinfo_search *srch = (struct pinfo_search *)data;

	if (index >= MAX_ARG_LEN)
		return 1;

	if (srch->argv[index] == '/')
		srch->idx_comm = index + 1;

	if (srch->argv[index] == ' ' ||
	    srch->argv[index] == '\0') {
		srch->argv[index] = '\0';
		return 1;
	}
	return 0;
}


static __always_inline int set_pinfo(const __u64 cookie)
{
	if (bpf_map_lookup_elem(&cookie_pinfo_map, &cookie))
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct pinfo pinfo = {};
	BPF_CORE_READ_INTO(&pinfo.pid, task, tgid);

	char argv[MAX_ARG_LEN];
	struct pinfo_search srch = {};
	srch.argv = argv;

	char *args = (char *)BPF_CORE_READ(task, mm, arg_start);
	bpf_core_read_user_str(argv, MAX_ARG_LEN, args);

	bpf_loop(MAX_ARG_LEN, find_last_slash_in_arg0, &srch, 0);

	u8 idx = srch.idx_comm;
	for (u8 i = 0; i < TASK_COMM_LEN; i++) {
		if (idx + i < MAX_ARG_LEN && argv[idx + i] != '\0') {
			pinfo.pname[i] = argv[idx + i];
		} else {
			pinfo.pname[i] = '\0';
			break;
		}
	}

	bpf_map_update_elem(&cookie_pinfo_map, &cookie, &pinfo, BPF_ANY);
	return 0;
}

SEC("cgroup/sock_create")
int cgroup_sock_create(struct bpf_sock *sk)
{
	set_pinfo(bpf_get_socket_cookie(sk));
	return 1;
}

SEC("cgroup/sock_release")
int cgroup_sock_release(struct bpf_sock *sk)
{
	__u64 cookie = bpf_get_socket_cookie(sk);
	bpf_map_delete_elem(&cookie_pinfo_map, &cookie);
	return 1;
}

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
	set_pinfo(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/connect6")
int cgroup_connect6(struct bpf_sock_addr *ctx)
{
	set_pinfo(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg4")
int cgroup_sendmsg4(struct bpf_sock_addr *ctx)
{
	set_pinfo(bpf_get_socket_cookie(ctx));
	return 1;
}

SEC("cgroup/sendmsg6")
int cgroup_sendmsg6(struct bpf_sock_addr *ctx)
{
	set_pinfo(bpf_get_socket_cookie(ctx));
	return 1;
}

static __always_inline u32
get_netns(struct sk_buff *skb)
{
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0)	{
		struct sock *sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	}

	return netns;
}

static __always_inline void
set_meta(struct meta *meta, struct sk_buff *skb, struct pt_regs *ctx)
{
	meta->pc = bpf_get_func_ip(ctx);
	meta->skb = (__u64)skb;
	meta->second_param = PT_REGS_PARM2(ctx);
	meta->mark = BPF_CORE_READ(skb, mark);
	meta->netns = get_netns(skb);
	meta->ifindex = BPF_CORE_READ(skb, dev, ifindex);
	BPF_CORE_READ_STR_INTO(&meta->ifname, skb, dev, name);
}

static __always_inline void
set_tuple(struct tuple *tpl, struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	u16 l4_off = BPF_CORE_READ(skb, transport_header);

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);

	u16 l3_total_len;
	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
		l3_total_len = bpf_ntohs(BPF_CORE_READ(ip4, tot_len));
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip6, nexthdr);
		tpl->l3_proto = ETH_P_IPV6;
		l3_total_len = bpf_ntohs(BPF_CORE_READ(ip6, payload_len));
	}
	u16 l3_hdr_len = l4_off - l3_off;

	u16 l4_hdr_len;
	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(tcp, source);
		tpl->dport= BPF_CORE_READ(tcp, dest);
		bpf_probe_read_kernel(&tpl->tcp_flags, sizeof(tpl->tcp_flags),
				    (void *)tcp + offsetof(struct tcphdr, ack_seq) + 5);
		l4_hdr_len = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff) * 4;
		tpl->payload_len = l3_total_len - l3_hdr_len - l4_hdr_len;
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(udp, source);
		tpl->dport= BPF_CORE_READ(udp, dest);
		tpl->payload_len = bpf_ntohs(BPF_CORE_READ(udp, len)) - sizeof(struct udphdr);
	}
}

static __always_inline int
handle_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
	u64 cookie = BPF_CORE_READ(skb, sk, __sk_common.skc_cookie.counter);
	if (!cookie)
		return 0;

	struct pinfo *pinfo = bpf_map_lookup_elem(&cookie_pinfo_map, &cookie);
	if (!pinfo || !!bpf_strncmp((char *)&pinfo->pname, 4, "curl"))
		return 0;

	struct event ev = {};
	set_meta(&ev.meta, skb, ctx);
	set_tuple(&ev.tuple, skb);

	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}

#define KPROBE_SKB_AT(X)						\
  SEC("kprobe/skb-" #X)							\
  int kprobe_skb_##X(struct pt_regs *ctx)				\
  {									\
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);      \
    return handle_skb(skb, ctx);					\
  }

KPROBE_SKB_AT(1)
KPROBE_SKB_AT(2)
KPROBE_SKB_AT(3)
KPROBE_SKB_AT(4)
KPROBE_SKB_AT(5)

char __license[] SEC("license") = "Dual BSD/GPL";
