#!/bin/sh

set -e

if [ ! -x "tools/ambry/ambry" ]; then
	echo "please compile first, i need the ambry tool"
	exit 1
fi

rm -rf test/secrets

mkdir test/secrets
mkdir test/secrets/flock-cafeba00
mkdir test/secrets/flock-aaaaaa00
mkdir test/secrets/flock-bbbbbb00

dd if=/dev/urandom bs=32 count=1 of=test/secrets/fe.key
dd if=/dev/urandom bs=32 count=1 of=test/secrets/badf00d.key

cp test/secrets/fe.key test/secrets/flock-cafeba00/000000fe.key
cp test/secrets/fe.key test/secrets/flock-aaaaaa00/000000fe.key
cp test/secrets/fe.key test/secrets/flock-bbbbbb00/000000fe.key

cp test/secrets/badf00d.key test/secrets/flock-cafeba00/0badf00d.key
cp test/secrets/badf00d.key test/secrets/flock-aaaaaa00/0badf00d.key
cp test/secrets/badf00d.key test/secrets/flock-bbbbbb00/0badf00d.key

rm -rf test/aaaaaa00
rm -rf test/bbbbbb00
rm -rf test/cafeba00

rm -f test/a.bundle
rm -f test/b.bundle
rm -f test/ab.bundle
rm -f test/ambry.keys

cd test

../tools/ambry/ambry generate aaaaaa00
../tools/ambry/ambry export aaaaaa00 bbbbbb00

../tools/ambry/ambry generate bbbbbb00
../tools/ambry/ambry export bbbbbb00 aaaaaa00

../tools/ambry/ambry bundle aaaaaa00 aaaaaa00 30 a.bundle
../tools/ambry/ambry bundle bbbbbb00 bbbbbb00 40 b.bundle
../tools/ambry/ambry bundle aaaaaa00 bbbbbb00 60 ab.bundle

../tools/ambry/ambry generate cafeba00
../tools/ambry/ambry bundle cafeba00 cafeba00 90 ambry.keys
