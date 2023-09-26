#!/bin/sh

set -e
set -x

ip link del left-link
ip link del right-link

ifconfig crypto-link down
brctl delbr crypto-link

iptables -A FORWARD -j DROP
