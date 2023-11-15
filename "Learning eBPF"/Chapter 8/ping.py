from bcc import BPF
import socket
import os
from time import sleep

b = BPF(src_file="ping.bpf.c")
interface = "eth0"

# XDP will be the first program hit when a packet is received ingress
fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

b.trace_print()
