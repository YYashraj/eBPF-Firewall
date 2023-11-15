from bcc import BPF

program = r'''
	BPF_PERF_OUTPUT(output); 
	struct data_t { 
		int pid;
		int uid;
		char command[16];
		char message[11];
	};

	//static char message[11] = "Hello World";
	
	int hello(void *ctx) {
		struct data_t data = {}; 
		char message[11] = "Hello World";
		 
		data.pid = bpf_get_current_pid_tgid() >> 32; 
		data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; 
		 
		bpf_get_current_comm(&data.command, sizeof(data.command)); 
		bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

		output.perf_submit(ctx, &data, sizeof(data)); 
		 
		return 0;
	}
'''

b = BPF(text=program) 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

'''
def print_event(cpu, data, size): 
	data = b["output"].event(data)
	print(f"{data.pid} {data.uid} {data.command.decode()} " + f"{data.message.decode()}")

b["output"].open_perf_buffer(print_event) 
while True: 
 	b.perf_buffer_poll()
'''

def print_data(cpu,data,size):
	data = b["output"].event(data)
	print(data)
	print(cpu)
	print(size)

	#attributes = vars(data)					## does not work ; is empty probably
	#for attr, value in attributes.items():
	#    print(f"{attr}: {value}")

	#attributes = vars(data)					## it is empty
	#print(attributes)

	print(data.__sizeof__)
	print(data.__sizeof__())
	 
	attributes = dir(data)
	for attr in attributes:
	    value = getattr(data, attr)
	    print(f"{attr}: {value}")

b["output"].open_perf_buffer(print_data) 
b.perf_buffer_poll()
