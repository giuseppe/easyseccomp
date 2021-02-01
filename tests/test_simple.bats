#!/usr/bin/env -S bats
# -*- mode: sh -*-

load helpers

@test "test EPERM" {
    cat > $PROGRAM <<EOF
// this is a comment to ignore
=> ERRNO(EPERM);
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT
}

@test "test ALLOW" {
    cat > $PROGRAM <<EOF
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT
}

@test "test ALLOW only mkdir" {
    cat > $PROGRAM <<EOF
// this is a comment to ignore
\$syscall == @mkdir => ALLOW();
// this is another comment to ignore
=> ERRNO(EPERM);
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim mknodat x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT
}

@test "test ALLOW only mkdir with !=" {
    cat > $PROGRAM <<EOF
// this is a comment to ignore
\$syscall != @mkdir => ERRNO(EPERM);
// this is another comment to ignore
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim mknodat x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT
}
