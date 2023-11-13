import socket
import struct

def is_an_ip(s):
    s_without_dot = s.replace('.', '')
    return s_without_dot.isdigit()

while True:
	# IP address in string format
	ip_address_str = input("Enter: ")

	'''
	if ip_address_str.isalpha():
		break
	'''

	if is_an_ip(ip_address_str)==False:
		break

	# Parse the IP address string and convert it to a 32-bit integer
	ip_address_int = struct.unpack("!I", socket.inet_aton(ip_address_str))[0]

	# Create a packed IP header with source and destination addresses
	ip_header_packed = struct.pack("!4s4s", ip_address_int.to_bytes(4, byteorder='big'), b'\x00\x00\x00\x00')  # Destination address is 0.0.0.0

	# Extract the source IP address from the packed IP header
	source_ip = ip_header_packed[:4]

	# Convert the source IP address back to a string (optional)
	source_ip_str = socket.inet_ntoa(source_ip)

	print(f"Source IP in integer format: {ip_address_int}")
	print(f"Source IP in string format: {source_ip_str}")
