#!/usr/bin/env -S bats
# -*- mode: sh -*-

@test "test args" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 == 1 => ERRNO(10);
\$arg1 == 1 => ERRNO(20);
\$arg2 == 1 => ERRNO(30);
\$arg3 == 1 => ERRNO(40);
\$arg4 == 1 => ERRNO(50);
\$arg5 == 1 => ERRNO(60);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 1 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 0 1 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 20" $BATS_TMPDIR/result

    sim mkdir x86_64 0 0 1 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 30" $BATS_TMPDIR/result

    sim mkdir x86_64 0 0 0 1 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 40" $BATS_TMPDIR/result

    sim mkdir x86_64 0 0 0 0 1 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 50" $BATS_TMPDIR/result

    sim mkdir x86_64 0 0 0 0 0 1 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 60" $BATS_TMPDIR/result
}

@test "test args GT/GE" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 > 10 => ERRNO(11);
\$arg0 >= 5 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 111 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 11" $BATS_TMPDIR/result

    sim mkdir x86_64 11 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 11" $BATS_TMPDIR/result

    sim mkdir x86_64 5 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 6 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 7 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 4 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result
}

@test "test args LT/LE" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 <= 5 => ERRNO(10);
\$arg0 < 10 => ERRNO(11);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 3 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 5 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    cat $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 9 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 11" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result
}

@test "test args with bitwise & EQ" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 & 1 == 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 3 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result
}

@test "test args with bitwise & NEQ" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 & 1 != 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 3 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result
}

@test "test args with bitwise & GE/GT" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 & 1 > 0 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 3 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    cat > $BATS_TMPDIR/program <<EOF
\$arg0 & 1 >= 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 3 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result
}

@test "test args with bitwise & LE/LT" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 & 1 < 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 3 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    cat > $BATS_TMPDIR/program <<EOF
\$arg0 & 2048 <= 100 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 2048 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result
}

@test "test multiple args in AND" {
    cat > $BATS_TMPDIR/program <<EOF
\$arg0 == 10 && \$arg1 == 20 => ERRNO(40);
=> ERRNO(10);
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 10 20 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 40" $BATS_TMPDIR/result

    sim mkdir x86_64 10 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 0 20 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir x86_64 0 0 30 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result
}
