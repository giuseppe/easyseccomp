#!/usr/bin/env -S bats
# -*- mode: sh -*-

load helpers

@test "test range" {
    cat > $BATS_TMPDIR/program <<EOF
\$syscall in (@mkdir, @unlink, @close) => ALLOW();
=> ERRNO(ENOSYS);
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    for i in mkdir unlink close; do
        sim $i x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
        grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
        grep "errno: 0" $BATS_TMPDIR/result
    done

    sim mknodat x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 38" $BATS_TMPDIR/result
}

@test "test multiple ranges" {
    cat > $BATS_TMPDIR/program <<EOF
\$syscall in (@dup, @accept, @socket) => ERRNO(ENOENT);
\$syscall in (@mkdir, @unlink, @close) => ALLOW();
=> ERRNO(EIO);
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    for i in dup accept socket; do
        sim $i x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
        grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
        grep "errno: 2" $BATS_TMPDIR/result
    done

    for i in mkdir unlink close; do
        sim $i x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
        grep SECCOMP_RET_ALLOW $BATS_TMPDIR/result
        grep "errno: 0" $BATS_TMPDIR/result
    done

    sim mknod x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 5" $BATS_TMPDIR/result
}
