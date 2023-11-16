import re
import sys

rules_path = "Rules.txt"
# session_path = "session_rules.txt"

blocks = dict()

def initialise():
	with open(rules_path, 'r') as Rules:
	    current_section = None
	    for line in Rules:
	        line = line.strip()
	        if line.endswith(":"):
	            current_section = line[:-1]  		## Removes the colon from the section name
	            blocks[current_section] = set()
	        elif current_section and line:  		## Check for non-empty lines in the current section
	            blocks[current_section].add(line)

initialise()										## populates blocks

def update_rules():
    with open(rules_path, 'w') as Rules:
        for section,blocked_list in blocks.items():
            Rules.write(f"{section}:\n\n")
            for blocked_item in blocked_list:
                Rules.write(f"\t{blocked_item}\n")
            Rules.write('\n')

def print_rules():								## prints the saved version of Rules
	print("-"*30)
	with open(rules_path, 'r') as Rules:
		for line in Rules:
			print(" " + line, end='')
	print("-"*30,"\n")

def Print(x): print(" " + x)

def print_updates():							## prints the unsaved version of Rules updated during execution
	print("-"*30)

	for i, (section,ips) in enumerate(blocks.items(), start=1):
		Print(f"{section}:\n")
		for ip in ips:
			Print(f"\t{ip}")
		
		# if (i != len(blocks)):					## When you have not reached the last section, leave an empty line
		print()

	print("-"*30,"\n")


# blocks["Blocked Incoming IPs"].add("2.2.2.2")
# blocks["Blocked Incoming IPs"].add("0.0.0.0")
# blocks["Blocked Outgoing IPs"].remove("0.0.0.0")
# blocks["Blocked Outgoing IPs"].add("1.1.1.1")

# print_rules()
# print_updates()
# update_rules()


while True:
	command = input().strip()

	if command == "exit":
		exit()

	elif command == "show Rules":
		print_rules()

	elif command == "show update":
		print_updates()

	elif command == "update Rules":
		update_rules()

	elif command == "undo changes":
		initialise()

	elif command[:5] != "Rules":
		print("Invalid Command")

	else:
		''' IP related commands '''

		if command == "Rules unblock IP all":
			bool = input("Are you certain you want to clear all the blocked IPs? (Y or N) ")

			# sys.stdout.write(f"\rAre you certain you want to clear all the blocked IPs? {bool}\n")
			# sys.stdout.flush()

			if "y" in bool.lower():
				blocks["Blocked Incoming IPs"] = set()
				blocks["Blocked Outgoing IPs"] = set()

			## else don't do anything
			continue

		if command == "Rules unblock I IP all":
			blocks["Blocked Incoming IPs"] = set()
			continue

		if command == "Rules unblock O IP all":
			blocks["Blocked Outgoing IPs"] = set()
			continue
			

		block_inc_ip_regex = r'^Rules block I IP (\d+\.\d+\.\d+\.\d+)$'
		block_out_ip_regex = r'^Rules block O IP (\d+\.\d+\.\d+\.\d+)$'
		block_both_ip_regex = r'^Rules block IP (\d+\.\d+\.\d+\.\d+)$'

		unblock_out_ip_regex = r'^Rules unblock O IP (\d+\.\d+\.\d+\.\d+)$'
		unblock_inc_ip_regex = r'^Rules unblock I IP (\d+\.\d+\.\d+\.\d+)$'
		unblock_both_regex = r'^Rules unblock IP (\d+\.\d+\.\d+\.\d+)$'


		if re.match(block_inc_ip_regex, command):
			ip = re.search(block_inc_ip_regex, command).group(1)
			blocks["Blocked Incoming IPs"].add(ip)
			continue

		elif re.match(block_out_ip_regex, command):
			ip = re.search(block_out_ip_regex, command).group(1)
			blocks["Blocked Outgoing IPs"].add(ip)
			continue
		
		elif re.match(block_both_ip_regex, command):
			ip = re.search(block_both_ip_regex, command).group(1)
			blocks["Blocked Incoming IPs"].add(ip)
			blocks["Blocked Outgoing IPs"].add(ip)
			continue

		elif re.match(unblock_out_ip_regex, command):
			ip = re.search(unblock_out_ip_regex, command).group(1)
			if ip in blocks["Blocked Outgoing IPs"]:
				blocks["Blocked Outgoing IPs"].remove(ip)
			else:
				print("The given IP is already enabled")
			continue

		elif re.match(unblock_inc_ip_regex, command):
			ip = re.search(unblock_inc_ip_regex, command).group(1)
			if ip in blocks["Blocked Incoming IPs"]:
				blocks["Blocked Incoming IPs"].remove(ip)
			else:
				print("The given IP is already enabled")
			continue

		elif re.match(unblock_both_regex, command):
			ip = re.search(unblock_both_regex, command).group(1)
			
			if ip in blocks["Blocked Incoming IPs"]:
				blocks["Blocked Incoming IPs"].remove(ip)
			else:
				print("The incoming traffic from the specified IP is already permitted.")
			
			if ip in blocks["Blocked Outgoing IPs"]:
				blocks["Blocked Outgoing IPs"].remove(ip)
			else:
				print("The outbound traffic from the specified IP is already permitted.")

			continue

		
		''' Port related commands '''

		parts = command.split()

		if len(parts) < 4 : 
			print("Invalid Command")
			continue

		action = parts[1] ; port = parts[-1]

		# block_src_port_regex = r'^Rules block sp (\d+)$'
		# block_dest_port_regex = r'^Rules block dp (\d+)$'
		# block_usrc_port_regex = r'^Rules block u sp (\d+)$'
		# block_udest_port_regex = r'^Rules block u dp (\d+)$'

		# unblock_src_port_regex = r'^Rules unblock sp (\d+)$'
		# unblock_dest_port_regex = r'^Rules unblock dp (\d+)$'
		# unblock_usrc_port_regex = r'^Rules unblock u sp (\d+)$'
		# unblock_udest_port_regex = r'^Rules unblock u dp (\d+)$'

		if action == "block":
			if parts[2] == "u":
				if parts[3] == "sp":
					blocks["Blocked from User Ports"].add(port)
				elif parts[3] == "dp":
					blocks["Blocked User to Ports"].add(port)

			elif parts[2] == "sp":
				blocks["Blocked from Ports"].add(port)

			elif parts[2] == "dp":
				blocks["Blocked to Ports"].add(port)


		elif action == "unblock":
			if parts[2] == "u":
				if parts[3] == "sp":
					if port in blocks["Blocked from User Ports"]:
						blocks["Blocked from User Ports"].remove(port)
					else:
						print("The given port is already enabled")

				elif parts[3] == "dp":
					if port in blocks["Blocked User to Ports"]:
						blocks["Blocked User to Ports"].remove(port)
					else:
						print("The given port is already enabled")

			elif parts[2] == "sp":
				if port in blocks["Blocked from Ports"]:
					blocks["Blocked from Ports"].remove(port)
				else:
					print("The given port is already enabled")

			elif parts[2] == "dp":
				if port in blocks["Blocked to Ports"]:
					blocks["Blocked to Ports"].remove(port)
				else:
					print("The given port is already enabled")

		else:
			print("Invalid Command")
