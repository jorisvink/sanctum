#!/bin/sh

export SANCTUM_SECCOMP_TRACE=1

./sanctum -c test/cathedral-1.conf
