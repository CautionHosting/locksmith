#!/bin/sh

echo "starting locksmithd"
/usr/bin/locksmithd
echo "locksmithd finished, starting oneshot"
source <(/usr/bin/locksmith-oneshot)
env
sleep 100000
