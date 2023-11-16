#include <linux/if_ether.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#define NS_IN_SEC 1000000000LL
#define MAX_PACKETS 100

BPF_ARRAY(data, u64, 3);


int xdp(struct xdp_md *ctx) {
  int t = 1, c = 2;
  u64 *count = data.lookup(&c);
  u64 *time = data.lookup(&t);
  if (time==NULL || *time == 0 || count==NULL) {
  	u64 now = bpf_ktime_get_ns();
  	u64 init = MAX_PACKETS;
  	data.update(&t, &now);
  	data.update(&c, &init);
  	return XDP_PASS;
  }
  
  if (*count == 0) {
        u64 now = bpf_ktime_get_ns();
        if (now - *time > NS_IN_SEC) {
        	*time = now;
        	*count = MAX_PACKETS;
        	return XDP_PASS;
        }
        else {
        	bpf_trace_printk("Blocked a packet");
        	return XDP_DROP;
  	}
  }
  
  else {
  	(*count)--;
  }
  return XDP_PASS;
}
