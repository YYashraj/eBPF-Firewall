# Allow only one IP address - code for allowing one server
#!/bin/bash

# Define the allowed source IP address
ALLOWED_IP=10.0.0.1

# Flush existing rules and set the default policy to DROP
iptables -F
iptables -P INPUT DROP

# Allow incoming packets from the allowed IP address
iptables -A INPUT -s $ALLOWED_IP -j ACCEPT

# Print the current firewall rules
iptables -L

echo "Firewall rules updated."

