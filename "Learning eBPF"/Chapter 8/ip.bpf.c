#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

static __always_inline unsigned short checker(void *data, void *data_end) {
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) { bpf_trace_printk("Hello, eBPF!\n"); return 0;}
	
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) { bpf_trace_printk("Hello, eBPF!\n"); return 0;}
	
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) { bpf_trace_printk("Hello, eBPF!\n"); return 0;}
	
	bpf_trace_printk("Here %d \n",iph->saddr);
	
	if (iph->saddr == 0) return 1;
	
	//bpf_trace_printk("Hello, eBPF!\n"); 
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
