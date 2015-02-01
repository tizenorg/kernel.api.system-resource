#!/bin/sh

CPU_CGROUP="/sys/fs/cgroup/cpu/background"
CPU_SHARE="50"
CPU_CONTROL_LIST="indicator net-config"

/bin/mkdir -pm 755 $CPU_CGROUP
echo $CPU_SHARE > $CPU_CGROUP/cpu.shares
for list in $CPU_CONTROL_LIST; do
        pid=`/usr/bin/pgrep $list`
        if [ "z${pid}" != "z" ]; then
                echo $pid > $CPU_CGROUP/cgroup.procs
        fi
done

