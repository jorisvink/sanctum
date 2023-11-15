#!/bin/sh

export SANCTUM_SECCOMP_TRACE=1

ip netns exec left ./sanctum -c test/left.conf
