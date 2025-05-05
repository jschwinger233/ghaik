// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define MAX_ARG_LEN 128
#define TASK_COMM_LEN 16


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

char __license[] SEC("license") = "Dual BSD/GPL";
