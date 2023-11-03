from bcc import BPF
import socket, struct
import os
from time import sleep
import ctypes as ct


b = BPF(src_file = "file.bpf.c")
interface = "eth0"


fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

blocked_ips_map = b.get_table("blocked_ips")

ip_to_block = input("Enter the ip to block: ")

ip_to_block_int = struct.unpack("!I", socket.inet_aton(ip_to_block))[0]
print(ip_to_block_int)

blocked_ips_map[ct.c_uint(ip_to_block_int)] = ct.c_int(1)

b.trace_print()
