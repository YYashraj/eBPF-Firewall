from bcc import BPF
import socket, struct
import os
from time import sleep
import ctypes as ct
from user_ip import get_local_ips
from tab_op import display_blocks
import signal
import subprocess
import sys

original_stdout = sys.stdout
# print(original_stdout)

def signal_handler(sig, frame):

    # sys.stdout.close()
    # print(sys.stdout)
    sys.stdout = original_stdout
    
    print("\nTerminated eBPF program.")
    
    os.system("sudo ip link set dev eth0 xdp off")
    os.system("sudo ip link set dev lo xdp off")
    
    sys.stdout.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


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


b = BPF(src_file = "firewall.bpf.c", cflags=["-w"])
interface = "lo"

fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

'''
# Load the XDP function for ingress
fx_ingress = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp("lo", fx_ingress, 0)  # Attach to ingress

# Load the same XDP function for egress
fx_egress = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp("eth0", fx_egress, 1)  # Attach to egress
'''

blocked_src_ips_map = b.get_table("blocked_src_ips")
blocked_dest_ips_map = b.get_table("blocked_dest_ips")

blocked_from_ports_map = b.get_table("blocked_incoming_from_ports")
blocked_to_ports_map = b.get_table("blocked_outgoing_to_ports")
blocked_from_system_ports_map = b.get_table("blocked_incoming_from_user_ports")
blocked_to_system_ports_map = b.get_table("blocked_outgoing_to_user_ports")


#ip_to_block = input("Enter the ip to block: ")

for ip_to_block in blocks["Blocked Incoming IPs"]:

	ip_to_block_int = struct.unpack("!I", socket.inet_aton(ip_to_block))[0]
	# print(ip_to_block, " : ", ip_to_block_int)
	blocked_src_ips_map[ct.c_uint(ip_to_block_int)] = ct.c_int(1)


for ip_to_block in blocks["Blocked Outgoing IPs"]:

    ip_to_block_int = struct.unpack("!I", socket.inet_aton(ip_to_block))[0]
    # print(ip_to_block, " : ", ip_to_block_int)
    blocked_dest_ips_map[ct.c_uint(ip_to_block_int)] = ct.c_int(1)
	

for port_to_block in blocks["Blocked from Ports"]:

	# print(port_to_block)
	blocked_from_ports_map[ct.c_uint(int(port_to_block))] = ct.c_int(1)


for port_to_block in blocks["Blocked to Ports"]:

    blocked_to_ports_map[ct.c_uint(int(port_to_block))] = ct.c_int(1)


for port_to_block in blocks["Blocked from User Ports"]:

    blocked_from_system_ports_map[ct.c_uint(int(port_to_block))] = ct.c_int(1)


for port_to_block in blocks["Blocked User to Ports"]:

    blocked_to_system_ports_map[ct.c_uint(int(port_to_block))] = ct.c_int(1)


user_ips = get_local_ips()
user_ips.append("10.7.52.103")
system_ips_map = b.get_table("user_system_ips")

blocks["User IPs"] = set()
for local_ip in user_ips:
    blocks["User IPs"].add(local_ip)
    local_int = struct.unpack("!I", socket.inet_aton(local_ip))[0]
    # print(local_ip, " : ", local_int)
    system_ips_map[ct.c_uint(int(local_int))] = ct.c_int(1)


display_blocks(blocks)
# print("System IPs:",user_ips)

log_file_path = "trace_log.txt"
sys.stdout = open(log_file_path, "w")

b.trace_print()
