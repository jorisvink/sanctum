#!/bin/sh

export SANCTUM_SECCOMP_TRACE=1

ip netns exec right ./sanctum -c test/shrine.conf
