from bcc import BPF
from time import sleep

program = r"""
//#include <linux/ptrace.h>

BPF_HASH(syscall_count);

int hello_sys_enter(struct __sk_buff *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 def = 0;
    u64 *count = syscall_count.lookup_or_init(&uid, &def);
    (*count)++;
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello_sys_enter")

i=0
while i<7: 
    sleep(2) 

    s = "Syscall counts by user ID - "
    for k, v in b["syscall_count"].items():
        s += f"UID {k.value}: {v.value} , "

    print(s)
    i+=1
