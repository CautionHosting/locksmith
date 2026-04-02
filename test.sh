#!/bin/sh

echo "starting locksmithd"
/usr/bin/locksmithd
echo "locksmithd finished, starting oneshot"
output="$(/usr/bin/locksmith-oneshot)"
eval "$output"
env
sleep 100000
