#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/ns_common.h>
#include <linux/fs.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <net/inet_sock.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_packet.h>
#include <linux/version.h>
#include <linux/log2.h>

struct leaf
{
	char executable[TASK_COMM_LEN];
};

struct parent_key
{
	char container_id[9];
};

// ルールを持ったarray map
BPF_HASH(inner1,u32, struct leaf, 32);
// コンテナIDをkeyにそのコンテナに関するルールを持ったarray mapを保持する．
BPF_HASH_OF_MAPS(parent_table, struct parent_key, "inner1", 10);
int trace_inet_bind(struct pt_regs *ctx)
{
	int inner_key = 1;
	struct leaf *l;

	struct parent_key hash_key = {{'t', 'e', 's', 't', '_', 'i', 'd', '1', '\0'}};
	void *inner_map;
	inner_map = parent_table.lookup(&hash_key);
	if (!inner_map)
		return 0;
	l = bpf_map_lookup_elem(inner_map, &inner_key);
	if (!l)
		return 0;

	bpf_trace_printk("%s \n", l->executable);

	struct parent_key hash_key2 = {{'t', 'e', 's', 't', '_', 'i', 'd','2', '\0'}};
	void *inner_map2;
	struct leaf *l2;

	inner_map2 = parent_table.lookup(&hash_key2);
	if (!inner_map2)
		return 0;
	l2 = bpf_map_lookup_elem(inner_map2, &inner_key);
	if (!l2)
		return 0;

	bpf_trace_printk("%s\n", l2->executable);
	return 0;
};