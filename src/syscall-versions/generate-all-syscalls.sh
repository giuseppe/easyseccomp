#!/usr/bin/env bash
set -euo pipefail
export LANG=C
OLD_WD="$(dirname "$0")"

if [ $# != 1 ]; then
    echo "Usage: $0 KERNEL_SOURCE" >&2
    exit 1
fi

DESTDIR=$(mktemp -d)
trap 'rm -rf $DESTDIR' EXIT

cd "$1"
for i in $(git tag -l | grep -Ev "next|-rc|2.6.11" | sort -r); do
    if git show "$i:arch/x86/entry/syscalls/syscall_64.tbl" > /dev/null 2>&1 ||
       git show "$i:arch/x86/syscalls/syscall_64.tbl" > /dev/null  2>&1; then
        # Dump all the archs
        (git ls-tree -r "$i" --name-only arch | grep '\.tbl$' | while read -r j; do
             git show "$i:$j"
         done
        ) | grep -v "^#" | awk 'NF {print $3}' | sort | uniq > "$DESTDIR/$i"
    elif git show "$i:arch/x86/include/asm/unistd_64.h" > /dev/null 2>&1; then
        (git ls-tree -r "$i" --name-only arch | grep 'arch/.*unistd.*\.h$' | while read -r j; do
             git show "$i:$j"
         done
        ) | sed -n -e '/^__SYSCALL(__NR/ {s/__SYSCALL(__NR_\([^,]\+\).*/\1/;p}' -e '/^__SYSCALL([0-9]\+, sys_/ {s/__SYSCALL([0-9]\+, sys_\([^,]\+\).*/\1/;p}' | sort | uniq > "$DESTDIR/$i"
    else
        (git ls-tree -r "$i" --name-only include | grep 'include/.*unistd*\.h$' | while read -r j; do
             git show "$i:$j"
         done
        ) | sed -n -e '/^__SYSCALL(__NR/ {s/__SYSCALL(__NR_\([^,]\+\).*/\1/;p}' -e '/^__SYSCALL([0-9]\+, sys_/ {s/__SYSCALL([0-9]\+, sys_\([^,]\+\).*/\1/;p}' | sort | uniq > "$DESTDIR/$i"
    fi
done

"$OLD_WD/generate-c-code.py" "$DESTDIR" > "$OLD_WD/syscall-versions.c.tmp"
mv "$OLD_WD/syscall-versions.c.tmp" "$OLD_WD/syscall-versions.c"
