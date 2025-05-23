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
#define MAX_UNWIND_DEPTH 50

const static bool TRUE = true;

struct config {
	u8 pname[TASK_COMM_LEN];
	u32 plen;
};

volatile const struct config CONFIG = {};

struct pinfo_search {
	char *argv;
	u8 idx_comm;
};

struct pinfo {
	u32 pid;
	char pname[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct pinfo);
	__uint(max_entries, 65535);
} cookie_pinfo_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sk_buff *);
	__type(value, bool);
	__uint(max_entries, 65535);
} skb_from_process SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct sk_buff *);
	__uint(max_entries, 65535);
} bp_skb_map SEC(".maps");

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
	u32 skb_len;
	u32 skb_linear_len;
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

static int __noinline find_last_slash_in_arg0(u32 index, void *data)
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


static __always_inline int set_pinfo(const u64 cookie)
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

	if (!!bpf_strncmp((char *)&pinfo.pname, CONFIG.plen, (char *)&CONFIG.pname))
		return 0;

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
	u64 cookie = bpf_get_socket_cookie(sk);
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
	meta->skb = (u64)skb;
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

	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip6, nexthdr);
		tpl->l3_proto = ETH_P_IPV6;
	}

	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(tcp, source);
		tpl->dport= BPF_CORE_READ(tcp, dest);
		bpf_probe_read_kernel(&tpl->tcp_flags, sizeof(tpl->tcp_flags),
				    (void *)tcp + offsetof(struct tcphdr, ack_seq) + 5);
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(udp, source);
		tpl->dport= BPF_CORE_READ(udp, dest);
	}

	tpl->skb_len = BPF_CORE_READ(skb, len);

	u32 data_end = BPF_CORE_READ(skb, tail);
	u32 data = !BPF_CORE_READ(skb, mac_len)
		? BPF_CORE_READ(skb, network_header)
		: BPF_CORE_READ(skb, mac_header);
	tpl->skb_linear_len = data_end - data;
}

static __always_inline int
handle_skb(struct sk_buff *skb, struct pt_regs *ctx)
{
	u64 bp;

	bool *from_process = bpf_map_lookup_elem(&skb_from_process, &skb);
	if (from_process && *from_process)
		goto cont;

	u64 cookie = BPF_CORE_READ(skb, sk, __sk_common.skc_cookie.counter);
	if (!cookie)
		return 0;

	struct pinfo *pinfo = bpf_map_lookup_elem(&cookie_pinfo_map, &cookie);
	if (!pinfo)
		return 0;

	bpf_map_update_elem(&skb_from_process, &skb, &TRUE, BPF_ANY);

cont:
	bp = ctx->bp;
	bpf_map_update_elem(&bp_skb_map, &bp, &skb, BPF_ANY);

	struct event ev = {};
	set_meta(&ev.meta, skb, ctx);
	set_tuple(&ev.tuple, skb);

	bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	return 0;
}

#define KPROBE_SKB_AT(X)						\
  SEC("kprobe.multi/skb-" #X)							\
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

SEC("kretprobe.multi/skb")
int kretprobe_skb(struct pt_regs *ctx)
{
	u64 bp = ctx->bp;
	bpf_map_delete_elem(&bp_skb_map, &bp);
	return 0;
}

SEC("kretprobe.multi/alloc_skb")
int kretprobe_alloc_skb(struct pt_regs *ctx)
{
	u64 bp = ctx->bp;
	struct sk_buff *nskb = (struct sk_buff *)ctx->ax;
	if (!nskb)
		return 0;

	if (bpf_map_lookup_elem(&skb_from_process, &nskb))
		return 0;

	u64 caller_bp;
	struct sk_buff **pskb;
	for (int depth=0; depth < MAX_UNWIND_DEPTH; depth++) {
		pskb = bpf_map_lookup_elem(&bp_skb_map, &bp);
		if (pskb && *pskb) {
			bpf_map_update_elem(&skb_from_process, &nskb, &TRUE, BPF_ANY);
			break;
		}

		if (bpf_probe_read_kernel(&caller_bp, sizeof(caller_bp), (void *)bp) < 0)
			break;

		if (!caller_bp)
			break;

		bp = caller_bp;
	}

	return 0;
}

SEC("kprobe/free_skb")
int kprobe_free_skb(struct pt_regs *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	bpf_map_delete_elem(&skb_from_process, &skb);
	return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
