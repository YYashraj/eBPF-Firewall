#!/bin/bash

TC=/sbin/tc
IF=h2-eth0
LIMIT=100mbit
DST_IP=10.0.0.1

create() {
  echo "== SHAPING INIT =="

  # Delete any previous qdiscs or classes attached to the interface
  $TC qdisc del dev $IF root 2>/dev/null

  # Create a class for shaping with a specified rate limit
  $TC qdisc add dev $IF root handle 1: htb default 30
  $TC class add dev $IF parent 1: classid 1:1 htb rate $LIMIT

  # Create a u32 filter to match packets with the specified destination IP address
  $TC filter add dev $IF protocol ip parent 1: prio 1 u32 match ip dst $DST_IP flowid 1:1

  echo "== SHAPING DONE =="
}

clean() {
  # You don't need to explicitly delete the root qdisc here
  echo "Cleaning up any previous qdiscs or classes..."
  $TC qdisc del dev $IF root 2>/dev/null
}

clean
create

