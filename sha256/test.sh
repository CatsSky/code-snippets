#!/bin/sh

echo "Creating random data for testing..."
dd if=/dev/random of=random1m bs=1k count=1024

ref=$(sha256sum random1m | awk '{printf $1}')
echo "reference sha256: $ref"

sha=$(./sha256.out < random1m)

if [ "$ref" = "$sha" ]; then
    echo "Test passed!"
else
    echo "Test not passed!"
    echo "The program output is: $sha"
fi

rm random1m