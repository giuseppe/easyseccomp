#!/usr/bin/env -S bats
# -*- mode: sh -*-

load helpers

@test "test in set" {
    cat > $PROGRAM <<EOF
\$syscall in (@mkdir, @unlink, @close) => ALLOW();
=> ERRNO(ENOSYS);
EOF
    easyseccomp < $PROGRAM > $BPF

    for i in mkdir unlink close; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ALLOW $RESULT
        grep "errno: 0" $RESULT
    done

    sim mknodat x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 38" $RESULT
}

@test "test not in set" {
    cat > $PROGRAM <<EOF
\$syscall not in (@mkdir, @unlink, @close) => ALLOW();
=> ERRNO(ENOSYS);
EOF
    easyseccomp < $PROGRAM > $BPF

    for i in mkdir unlink close; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ERRNO $RESULT
        grep "errno: 38" $RESULT
    done

    sim mknodat x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT
}

@test "test multiple ranges" {
    cat > $PROGRAM <<EOF
\$syscall in (@dup, @accept, @socket) => ERRNO(ENOENT);
\$syscall in (@mkdir, @unlink, @close) => ALLOW();
=> ERRNO(EIO);
EOF
    easyseccomp < $PROGRAM > $BPF

    for i in dup accept socket; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ERRNO $RESULT
        grep "errno: 2" $RESULT
    done

    for i in mkdir unlink close; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ALLOW $RESULT
        grep "errno: 0" $RESULT
    done

    sim mknod x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 5" $RESULT
}

@test "test in set with big range" {
    range=$(seq 1 1999 | tr '\n' ',')
    cat > $PROGRAM <<EOF
\$syscall in ($range 2000) => ALLOW();
=> ERRNO(ENOSYS);
EOF
    cp $PROGRAM /tmp/program-1
    easyseccomp < $PROGRAM > $BPF

    for i in 1 2 3 4 5 10 20 30 110 500 555 1999 2000; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        echo TRY $i
        grep SECCOMP_RET_ALLOW $RESULT
        grep "errno: 0" $RESULT
    done

    for i in 0 2001 3000; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ERRNO $RESULT
        grep "errno: 38" $RESULT
    done
}

@test "test in set with big shuffled range" {
    range=$(seq 1 1999 | shuf | tr '\n' ',')
    cat > $PROGRAM <<EOF
\$syscall in ($range 2000) => ALLOW();
=> ERRNO(ENOSYS);
EOF
    cp $PROGRAM /tmp/program-1
    easyseccomp < $PROGRAM > $BPF

    for i in 1 2 3 4 5 10 20 30 110 500 555 1999 2000; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        echo TRY $i
        grep SECCOMP_RET_ALLOW $RESULT
        grep "errno: 0" $RESULT
    done

    for i in 0 2001 3000; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ERRNO $RESULT
        grep "errno: 38" $RESULT
    done
}

@test "test in set with multiple ranges" {
    range1=$(seq 1 10 | tr '\n' ',')
    range2=$(seq 21 30 | tr '\n' ',')
    range3=$(seq 41 50 | tr '\n' ',')
    cat > $PROGRAM <<EOF
\$syscall in ($range1 $range2 $range3 2000,3000) => ALLOW();
=> ERRNO(ENOSYS);
EOF
    cp $PROGRAM /tmp/program-1
    easyseccomp < $PROGRAM > $BPF

    for i in 1 5 10 21 25 30 41 44 49 50 2000 3000; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ALLOW $RESULT
        grep "errno: 0" $RESULT
    done

    for i in 0 11 15 20 31 32 35 40 51 52 1000 1999 2001 2999 3001; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ERRNO $RESULT
        grep "errno: 38" $RESULT
    done
}

@test "test in set without ranges" {
    range=$(seq 1 2 20 | tr '\n' ',')
    cat > $PROGRAM <<EOF
\$syscall in ($range 2000) => ALLOW();
=> ERRNO(ENOSYS);
EOF
    cp $PROGRAM /tmp/program-1
    easyseccomp < $PROGRAM > $BPF

    for i in 1 3 5 7 9 11 13 15 17 19 2000; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        echo TRY $i
        grep SECCOMP_RET_ALLOW $RESULT
        grep "errno: 0" $RESULT
    done

    for i in 0 2 4 6 8 10 12 14 16 18 20; do
        sim $i x86_64 0 0 0 0 0 0 < $BPF > $RESULT
        grep SECCOMP_RET_ERRNO $RESULT
        grep "errno: 38" $RESULT
    done
}
