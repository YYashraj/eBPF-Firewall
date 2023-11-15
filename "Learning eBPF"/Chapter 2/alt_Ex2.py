from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_execve, u64);
BPF_HASH(counter_openat, u64);

int hello_execve(void *ctx) {
   u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   u32 *p = counter_execve.lookup(&uid);
   if (p != 0) {
      (*p)++;
   } else {
      u32 initial_count = 1;
      counter_execve.update(&uid, &initial_count);
   }
   return 0;
}

int hello_openat(void *ctx) {
   u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   u32 *p = counter_openat.lookup(&uid);
   if (p != 0) {
      (*p)++;
   } else {
      u32 initial_count = 1;
      counter_openat.update(&uid, &initial_count);
   }
   return 0;
}
"""

b = BPF(text=program)

syscall_execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall_execve, fn_name="hello_execve")

syscall_openat = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall_openat, fn_name="hello_openat")

try:
    sleep(5)  # Adjust the duration as needed
finally:
   s_execve = "execve counts:\n"
   for k, v in b["counter_execve"].items():
      s_execve += f"UID {k.value}: {v.value}\n"
    
   s_openat = "openat counts:\n"
   for k, v in b["counter_openat"].items():
      s_openat += f"UID {k.value}: {v.value}\n"
    
   print(s_execve)
   print(s_openat)
