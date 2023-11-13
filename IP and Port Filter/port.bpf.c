#include <linux/if_ether.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


BPF_HASH(blocked_src_ips, u32, u32);
BPF_HASH(blocked_dest_ips, u32, u32);
BPF_HASH(user_system_ips, u32, u32);

BPF_HASH(blocked_incoming_from_ports, u16, u16);				// src_port filter
BPF_HASH(blocked_outgoing_to_ports, u16, u16);					// dest port filter
BPF_HASH(blocked_incoming_from_user_ports, u16, u16);		// 
BPF_HASH(blocked_outgoing_to_user_ports, u16, u16);


static __always_inline unsigned short checker(void *data, void *data_end) {

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) return 0;
	
	/* check whether the packet is IPv4 */
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return 0;
	
	/* advances the pointer over ethernet header to network header */
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return 0;

	
	/*** IP-based FILTERING ***/

	/* check whether the packet is coming from a blocked IP */
	u32 source_ip = bpf_ntohl(iph->saddr);
	u32 *blocked_src = blocked_src_ips.lookup(&source_ip);
	if (blocked_src){
		bpf_trace_printk("Blocked a packet from source ip: %u", source_ip);
		return 1;	
	} 

	/* check whether the packet is being sent to a blocked IP */
	u32 dest_ip = bpf_ntohl(iph->daddr);
  u32 *blocked_dest = blocked_dest_ips.lookup(&dest_ip);
  if (blocked_dest) {
      bpf_trace_printk("Blocked a packet to destination ip: %u\n", dest_ip);
      return 1;
  }


  /*** PORT-based FILTERING ***/

  // Check whether the packet is sent or received by the user's system
  // A hit in the map means yes it is being sent by our system
  u32 *user_system = user_system_ips.lookup(&source_ip);
	
	if (iph->protocol == 0x06) {
			//bpf_trace_printk("Here comes a TCP packet!");

	    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	    if (tcp + sizeof(struct tcphdr) > data_end) return 0;

	    u16 source_port = bpf_ntohs(tcp->source);
	    
	    u16 dest_port = bpf_ntohs(tcp->dest);
	    u16 *block_dest = blocked_ports.lookup(&dest_port);

	    /*
	    //bpf_trace_printk("%p", block);
	    if (block){	   
	    	// bpf_trace_printk("Source IP: %u\n", iph->saddr);
	    	// bpf_trace_printk("Dest IP: %u\n", iph->daddr);
	    	// bpf_trace_printk("Source Port: %u\n", source_port); 	
	    	bpf_trace_printk("\nBlocked a tcp packet from port: %u\n", source_port);
	    	return 1;
	    }
	    //else bpf_trace_printk("%d", bpf_ntohs(tcp->source));
	    */

	    if (user_system){
	    		// The user is sending this packet

	    		u16 *block_src = blocked_ports.lookup(&source_port);
	    }
	}
	
	if (iph->protocol == 0x11) {
			//bpf_trace_printk("hi, udp here");

	    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	    if (udp + sizeof(struct udphdr) > data_end) return 0;

	    u16 source_port = bpf_ntohs(udp->source);
	    u16 *block_src = blocked_ports.lookup(&source_port);

	    u16 dest_port = bpf_ntohs(udp->dest);
	    u16 *block_dest = blocked_ports.lookup(&dest_port);
	    
	    if (block){
	    	bpf_trace_printk("Blocked a udp packet from port: %u", source_port);
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