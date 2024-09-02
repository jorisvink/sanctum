#!/bin/sh

if [ $# -ne 1 ]; then
	echo "usage: ./test/linux-right.sh [config]"
	exit 1
fi

ip netns exec right ./sanctum -c $1
