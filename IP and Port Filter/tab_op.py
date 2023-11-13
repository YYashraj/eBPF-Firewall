import socket
import struct
from tabulate import tabulate

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def format_blocks(blocks):
    formatted_blocks = {}

    for key, values in blocks.items():
        if "IPs" in key:
            formatted_values = [f"{ip} : {ip_to_int(ip)}" for ip in values]
            formatted_blocks[key] = formatted_values
        else:
            formatted_blocks[key] = values

    return formatted_blocks

def display_blocks(blocks):
    formatted_blocks = format_blocks(blocks)

    for key, values in formatted_blocks.items():
        print(f"{key}:")
        print(tabulate([(value,) for value in values]))
        # print(tabulate([(value,) for value in values], headers=["Blocked Value"]))
        #print(tabulate(values, headers=["IP", "Blocked Value"]))
        # print("\n")


if __name__ == "__main__":
    blocks = {
        "Blocked Incoming IPs": {"192.168.1.1", "10.0.0.1"},
        "Blocked Outgoing IPs": {"8.8.8.8", "1.1.1.1"},
        "Blocked Incoming Ports": {"80", "443"},
        "Blocked Outgoing Ports": {"8080", "9090"},
    }

    display_blocks(blocks)
