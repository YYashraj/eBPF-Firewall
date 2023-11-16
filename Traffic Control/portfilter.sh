#!/bin/bash
## Only server from a particular port
# Define the allowed port number
ALLOWED_PORT=8080

# Flush existing rules
iptables -F

# Set default policies to DROP for INPUT, OUTPUT, and FORWARD
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow incoming and outgoing packets on the allowed port
iptables -A INPUT -p tcp --dport $ALLOWED_PORT -j ACCEPT
iptables -A INPUT -p udp --dport $ALLOWED_PORT -j ACCEPT
iptables -A OUTPUT -p tcp --dport $ALLOWED_PORT -j ACCEPT
iptables -A OUTPUT -p udp --dport $ALLOWED_PORT -j ACCEPT

# Allow related and established connections
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Print the current firewall rules
iptables -L

echo "Firewall rules updated to allow incoming and outgoing traffic on port $ALLOWED_PORT."

