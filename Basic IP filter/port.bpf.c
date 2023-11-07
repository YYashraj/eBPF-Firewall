#include <linux/if_ether.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

BPF_HASH(blocked_ips, u32, u32);
BPF_HASH(blocked_ports, u16, u16);

static __always_inline unsigned short checker(void *data, void *data_end) {
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) return 0;
	
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return 0;
	
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return 0;
	
	u32 source_ip = bpf_ntohl(iph->saddr);
	u32 *blocked = blocked_ips.lookup(&source_ip);
	if (blocked){
		bpf_trace_printk("Blocked a packet from ip: %u", source_ip);
		return 1;	
	} 
	
	if (iph->protocol == 0x06) {
			//bpf_trace_printk("Here comes a TCP packet!");

	    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	    if (tcp + sizeof(struct tcphdr) > data_end) return 0;
	    u16 *block = blocked_ports.lookup(&(tcp->source));

	    if (block){
	    	u16 source_port = bpf_ntohs(tcp->source);
	    	bpf_trace_printk("Blocked a packet from port: %u", source_port);
	    	return 1;
	    }
	    else bpf_trace_printk("Here comes a TCP packet!");
	}
	
	if (iph->protocol == 0x11) {
	    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	    if (udp + sizeof(struct udphdr) > data_end) return 0;
	    u16 *block = blocked_ports.lookup(&(udp->source));
	    
	    if (block){
	    	u16 source_port = bpf_ntohs(udp->source);
	    	bpf_trace_printk("Blocked a packet from port: %u", source_port);
	    	return 1;
	    }
	}
	
	return 0;
}

int xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (checker(data, data_end)) {
        //bpf_trace_printk("stopped a packet");
        return XDP_DROP;
  }

    return XDP_PASS;
}