from bcc import BPF
import socket, struct
import os
from time import sleep
import ctypes as ct

blocks = {}
with open("Rules.txt", 'r') as Rules:
    current_section = None
    for line in Rules:
        line = line.strip()
        if line.endswith(":"):
            current_section = line[:-1]  		
            blocks[current_section] = set()
        elif current_section and line:  		
            blocks[current_section].add(line)


b = BPF(src_file = "port.bpf.c")
interface = "eth0"


fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)
blocked_ips_map = b.get_table("blocked_ips")
blocked_ports_map = b.get_table("blocked_ports")

#ip_to_block = input("Enter the ip to block: ")

for ip_to_block in blocks["Blocked Incoming IPs"]:
	ip_to_block_int = struct.unpack("!I", socket.inet_aton(ip_to_block))[0]
	print(ip_to_block, " : ", ip_to_block_int)
	blocked_ips_map[ct.c_uint(ip_to_block_int)] = ct.c_int(1)
	
for port_to_block in blocks["Blocked Incoming Ports"]:
	print(port_to_block)
	blocked_ports_map[ct.c_uint(int(port_to_block))] = ct.c_int(1)
    
b.trace_print()