#!/bin/sh

cat /run.sh

echo "starting locksmithd"
/usr/bin/locksmithd2
echo "locksmithd finished, starting oneshot"
source <(/usr/bin/locksmith-oneshot2)
env
sleep 100000
