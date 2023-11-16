#!/usr/bin/python3
from bcc import BPF

b = BPF(src_file = "limiter.bpf.c")
interface = "h1-eth0"

fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

while (True):
	continue
