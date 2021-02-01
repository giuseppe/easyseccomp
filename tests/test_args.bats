#!/usr/bin/env -S bats
# -*- mode: sh -*-

load helpers

@test "test args" {
    cat > $PROGRAM <<EOF
\$arg0 == 1 => ERRNO(10);
\$arg1 == 1 => ERRNO(20);
\$arg2 == 1 => ERRNO(30);
\$arg3 == 1 => ERRNO(40);
\$arg4 == 1 => ERRNO(50);
\$arg5 == 1 => ERRNO(60);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 1 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 0 1 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 20" $RESULT

    sim mkdir x86_64 0 0 1 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 30" $RESULT

    sim mkdir x86_64 0 0 0 1 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 40" $RESULT

    sim mkdir x86_64 0 0 0 0 1 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 50" $RESULT

    sim mkdir x86_64 0 0 0 0 0 1 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 60" $RESULT
}

@test "test args GT/GE" {
    cat > $PROGRAM <<EOF
\$arg0 > 10 => ERRNO(11);
\$arg0 >= 5 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 111 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 11" $RESULT

    sim mkdir x86_64 11 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 11" $RESULT

    sim mkdir x86_64 5 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 6 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 7 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 4 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT
}

@test "test args LT/LE" {
    cat > $PROGRAM <<EOF
\$arg0 <= 5 => ERRNO(10);
\$arg0 < 10 => ERRNO(11);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 3 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 5 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    cat $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 9 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 11" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT
}

@test "test args with bitwise & EQ" {
    cat > $PROGRAM <<EOF
\$arg0 & 1 == 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 3 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT
}

@test "test args with bitwise & NEQ" {
    cat > $PROGRAM <<EOF
\$arg0 & 1 != 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 3 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT
}

@test "test args with bitwise & GE/GT" {
    cat > $PROGRAM <<EOF
\$arg0 & 1 > 0 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 3 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    cat > $PROGRAM <<EOF
\$arg0 & 1 >= 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 3 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT
}

@test "test args with bitwise & LE/LT" {
    cat > $PROGRAM <<EOF
\$arg0 & 1 < 1 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 3 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    cat > $PROGRAM <<EOF
\$arg0 & 2048 <= 100 => ERRNO(10);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 2048 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT
}

@test "test multiple args in AND" {
    cat > $PROGRAM <<EOF
\$arg0 == 10 && \$arg1 == 20 && \$arg2 == 30 => ERRNO(40);
=> ERRNO(10);
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 10 20 30 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 40" $RESULT

    sim mkdir x86_64 10 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 0 20 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir x86_64 0 0 30 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT
}

@test "test multiple args in AND and bitwise &" {
    cat > $PROGRAM <<EOF
\$arg0 & 10 == 10 && \$arg1 == 20 && \$arg2 & 30 == 30 => ERRNO(40);
=> ERRNO(10);
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 10 20 30 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 40" $RESULT

    sim mkdir x86_64 3 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT
}
