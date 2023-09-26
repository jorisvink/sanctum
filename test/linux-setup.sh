#!/bin/sh

set -e
set -x

#ip netns add left
#ip netns add right

ip link add dev left-link type veth peer name cry.left
ip link add dev right-link type veth peer name cry.right

ip link set left-link up
ip link set right-link up

brctl addbr crypto-link
brctl addif crypto-link left-link
brctl addif crypto-link right-link

ip link set crypto-link up

ip link set cry.left netns left
ip link set cry.right netns right

ip netns exec left ifconfig cry.left 1.1.1.1 netmask 255.255.255.0
ip netns exec right ifconfig cry.right 1.1.1.2 netmask 255.255.255.0

iptables -A FORWARD -j ACCEPT
