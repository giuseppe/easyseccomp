#!/usr/bin/env -S bats
# -*- mode: sh -*-

@test "test EPERM" {
    cat > $BATS_TMPDIR/program <<EOF
// this is a comment to ignore
=> ERRNO(EPERM);
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result
}

@test "test ALLOW" {
    cat > $BATS_TMPDIR/program <<EOF
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result
}

@test "test ALLOW only mkdir" {
    cat > $BATS_TMPDIR/program <<EOF
// this is a comment to ignore
\$syscall == @mkdir => ALLOW();
// this is another comment to ignore
=> ERRNO(EPERM);
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    sim mknodat x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result
}

@test "test ALLOW only mkdir with !=" {
    cat > $BATS_TMPDIR/program <<EOF
// this is a comment to ignore
\$syscall != @mkdir => ERRNO(EPERM);
// this is another comment to ignore
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
    grep "errno: 0" $BATS_TMPDIR/result

    sim mknodat x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result
}
