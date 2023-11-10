import re

rules_path = "Rules.txt"
session_path = "session_rules.txt"

blocks = dict()

with open(rules_path, 'r') as Rules:
    current_section = None
    for line in Rules:
        line = line.strip()
        if line.endswith(":"):
            current_section = line[:-1]  		## Removes the colon from the section name
            blocks[current_section] = set()
        elif current_section and line:  		## Check for non-empty lines in the current section
            blocks[current_section].add(line)

def update_rules():
    with open(rules_path, 'w') as Rules:
        for section,ips in blocks.items():
            Rules.write(f"{section}:\n\n")
            for ip in ips:
                Rules.write(f"\t{ip}\n")
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

	elif command[:5] != "Rules":
		print("Invalid Command")

	else:
		block_ip_regex = r'^Rules block I IP (\d+\.\d+\.\d+\.\d+)$'
		unblock_ip_regex = r'^Rules unblock O IP (\d+\.\d+\.\d+\.\d+)$'
		block_both_regex = r'^Rules block IP (\d+\.\d+\.\d+\.\d+)$'
		unblock_both_regex = r'^Rules unblock IP (\d+\.\d+\.\d+\.\d+)$'

		if re.match(block_ip_regex, command):
			ip = re.search(block_ip_regex, command).group(1)
			blocks["Blocked Incoming IPs"].add(ip)

		elif re.match(unblock_ip_regex, command):
			ip = re.search(unblock_ip_regex, command).group(1)
			if ip in blocks["Blocked Outgoing IPs"]:
				blocks["Blocked Outgoing IPs"].remove(ip)
			else:
				print("The given IP is already enabled")

		elif re.match(block_both_regex, command):
			ip = re.search(block_both_regex, command).group(1)
			blocks["Blocked Incoming IPs"].add(ip)
			blocks["Blocked Outgoing IPs"].add(ip)

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

		else:
			print("Invalid Command")
		