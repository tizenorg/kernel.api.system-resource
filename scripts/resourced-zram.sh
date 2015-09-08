#!/bin/sh

FILE="/sys/block/zram0"
SWAP="/dev/zram0"
RATE="20"

Mem=`cat /proc/meminfo | grep "MemTotal" | awk '{print $2}'`

if [ $Mem -lt 200000 ]; then
        SIZE="8388608"
elif [ $Mem -ge 200000 -a $Mem -lt 900000 ]; then
        SIZE=$((Mem * RATE / 100 * 1024))
elif [ $Mem -ge 900000 ]; then
        SIZE="134217728"
fi

if [ ! -e $FILE ]; then
	/sbin/modprobe zram num_devices=1
fi
/bin/echo $SIZE > $FILE/disksize
/sbin/mkswap $SWAP
