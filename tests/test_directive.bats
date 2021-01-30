#!/usr/bin/env -S bats
# -*- mode: sh -*-

load helpers

@test "test ALLOW mkdir with directive" {
    cat > $BATS_TMPDIR/program <<EOF
#ifdef ALLOW_MKDIR
\$syscall == @mkdir => ALLOW();
#endif
=> ERRNO(EPERM);
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    sim open x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    easyseccomp -d ALLOW_MKDIR < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    sim open x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result
}

@test "test ALLOW mkdir with negative directive" {
    cat > $BATS_TMPDIR/program <<EOF
#ifndef ALLOW_MKDIR
\$syscall == @mkdir => ALLOW();
#endif
=> ERRNO(EPERM);
EOF
    easyseccomp -d ALLOW_MKDIR < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    sim open x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    sim open x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result
}

@test "test ALLOW mkdir with recursive directive" {
    cat > $BATS_TMPDIR/program <<EOF
#ifdef NEVER_ALLOWED
#ifdef ALLOW_MKDIR
\$syscall == @mkdir => ALLOW();
#endif
#endif
=> ERRNO(EPERM);
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    sim open x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    easyseccomp -d ALLOW_MKDIR < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    sim open x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result
}
