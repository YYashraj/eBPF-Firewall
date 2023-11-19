import psutil
import socket


def get_local_ips():
    # Get a list of network interfaces and their associated IP addresses
    network_info = psutil.net_if_addrs()

    # Extract the IPv4 addresses from the network information
    ipv4_addresses = [
        addr.address
        for interface, addresses in network_info.items()
        for addr in addresses
        if addr.family == socket.AF_INET
    ]

    return ipv4_addresses


# Check if the module is being run as the main program
if __name__ == "__main__":
    # If it is the main program, get and print the local IP addresses
    local_ips = get_local_ips()
    print(local_ips)


'''
print(socket.AF_INET, end="\n\n")

network_info = psutil.net_if_addrs()
print(network_info)
print()

for interface, addresses in network_info.items():
    print(f"{interface} : {addresses}")
    print()

    for addr in addresses:
            print(f"address: {addr.address} , family: {addr.family}\n")
'''