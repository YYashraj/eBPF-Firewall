#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

BPF_HASH(blocked_ips, u32, u32);

static __always_inline unsigned short checker(void *data, void *data_end) {
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) return 0;
	
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return 0;
	
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return 0;
	
	u32 source_ip = bpf_ntohl(iph->saddr);				//ensure big-endian
	u32 *blocked = blocked_ips.lookup(&source_ip);
	
	if (blocked) return 1;
	return 0;
}

int xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (checker(data, data_end)) {
        bpf_trace_printk("stopped a packet");
        return XDP_DROP;
  }

    return XDP_PASS;
}
