#!/usr/bin/env -S bats
# -*- mode: sh -*-

load helpers

@test "test ALLOW mkdir with directive" {
    cat > $PROGRAM <<EOF
#ifdef ALLOW_MKDIR
\$syscall == @mkdir => ALLOW();
#endif
=> ERRNO(EPERM);
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    sim open x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    easyseccomp -d ALLOW_MKDIR < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim open x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT
}

@test "test ALLOW mkdir with negative directive" {
    cat > $PROGRAM <<EOF
#ifndef ALLOW_MKDIR
\$syscall == @mkdir => ALLOW();
#endif
=> ERRNO(EPERM);
EOF
    easyseccomp -d ALLOW_MKDIR < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    sim open x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim open x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT
}

@test "test ALLOW mkdir with recursive directive" {
    cat > $PROGRAM <<EOF
#ifdef NEVER_ALLOWED
#ifdef ALLOW_MKDIR
\$syscall == @mkdir => ALLOW();
#endif
#endif
=> ERRNO(EPERM);
EOF
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    sim open x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    easyseccomp -d ALLOW_MKDIR < $PROGRAM > $BPF

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    sim open x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT
}
