#!/bin/sh

if [ $# -ne 1 ]; then
	echo "usage: ./test/linux-left.sh [config]"
	exit 1
fi

ip netns exec left ./sanctum -c $1
