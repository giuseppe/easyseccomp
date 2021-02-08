#!/bin/sh

if test $# != 1; then
    echo "Usage: $0 KERNEL_SOURCE" >&2
    exit 1
fi

export LANG=C
set -euxo pipefail

cd $1
DESTDIR=$(mktemp -d)

trap "rm -rf $DESTDIR" EXIT

for i in `git tag -l | egrep -v next\|-rc\|2.6.11 | sort -r`; do
    if git show $i:arch/x86/entry/syscalls/syscall_64.tbl > /dev/null 2>&1 ||
       git show $i:arch/x86/syscalls/syscall_64.tbl > /dev/null  2>&1; then
        # Dump all the archs
        (git ls-tree -r $i --name-only arch | grep '\.tbl$' | while read j; do
             git show $i:$j
         done
        ) | grep -v ^# | awk 'NF {print $3}' | sort | uniq > $DESTDIR/$i
    elif git show $i:arch/x86/include/asm/unistd_64.h > /dev/null 2>&1; then
        (git ls-tree -r $i --name-only arch | grep 'arch/.*unistd.*\.h$' | while read j; do
             git show $i:$j
         done
        ) | sed -n -e '/^__SYSCALL(__NR/ {s/__SYSCALL(__NR_\([^,]\+\).*/\1/;p}' -e '/^__SYSCALL([0-9]\+, sys_/ {s/__SYSCALL([0-9]\+, sys_\([^,]\+\).*/\1/;p}' | sort | uniq > $DESTDIR/$i
    else
        (git ls-tree -r $i --name-only include | grep 'include/.*unistd*\.h$' | while read j; do
             git show $i:$j
         done
        ) | sed -n -e '/^__SYSCALL(__NR/ {s/__SYSCALL(__NR_\([^,]\+\).*/\1/;p}' -e '/^__SYSCALL([0-9]\+, sys_/ {s/__SYSCALL([0-9]\+, sys_\([^,]\+\).*/\1/;p}' | sort | uniq > $DESTDIR/$i
    fi
done

$(dirname $0)/generate-c-code.py $DESTDIR > $(dirname $0)/syscall-versions.c.tmp
mv $(dirname $0)/syscall-versions.c.tmp $(dirname $0)/syscall-versions.c
