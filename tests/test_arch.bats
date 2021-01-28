#!/usr/bin/env -S bats
# -*- mode: sh -*-

@test "test arches" {
    cat > $BATS_TMPDIR/program <<EOF
\$arch == @x86 => ERRNO(1);
\$arch == @x86_64 => ERRNO(2);
\$arch == @x32 => ERRNO(3);
\$arch == @arm => ERRNO(4);
\$arch == @aarch64 => ERRNO(5);
\$arch == @mips => ERRNO(6);
\$arch == @mipsel => ERRNO(7);
\$arch == @mips64 => ERRNO(8);
\$arch == @mipsel64 => ERRNO(9);
\$arch == @mips64n32 => ERRNO(10);
\$arch == @mipsel64n32 => ERRNO(11);
\$arch == @parisc => ERRNO(12);
\$arch == @parisc64 => ERRNO(13);
\$arch == @ppc => ERRNO(14);
\$arch == @ppc64 => ERRNO(15);
\$arch == @ppc64le => ERRNO(16);
\$arch == @s390 => ERRNO(17);
\$arch == @s390x => ERRNO(18);
=> ALLOW();
EOF
    easyseccomp < $BATS_TMPDIR/program > $BATS_TMPDIR/bpf

    sim mkdir x86 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 1" $BATS_TMPDIR/result

    sim mkdir x86_64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 2" $BATS_TMPDIR/result

    sim mkdir x32 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 3" $BATS_TMPDIR/result

    sim mkdir arm 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 4" $BATS_TMPDIR/result

    sim mkdir aarch64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 5" $BATS_TMPDIR/result

    sim mkdir mips 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 6" $BATS_TMPDIR/result

    sim mkdir mipsel 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 7" $BATS_TMPDIR/result

    sim mkdir mips64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 8" $BATS_TMPDIR/result

    sim mkdir mipsel64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 9" $BATS_TMPDIR/result

    sim mkdir mips64n32 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 10" $BATS_TMPDIR/result

    sim mkdir mipsel64n32 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 11" $BATS_TMPDIR/result

    sim mkdir parisc 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 12" $BATS_TMPDIR/result

    sim mkdir parisc64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 13" $BATS_TMPDIR/result

    sim mkdir ppc 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 14" $BATS_TMPDIR/result

    sim mkdir ppc64 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 15" $BATS_TMPDIR/result

    sim mkdir ppc64le 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 16" $BATS_TMPDIR/result

    sim mkdir s390 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 17" $BATS_TMPDIR/result

    sim mkdir s390x 0 0 0 0 0 0 < $BATS_TMPDIR/bpf > $BATS_TMPDIR/result
    grep SECCOMP_RET_ERRNO $BATS_TMPDIR/result
    grep "errno: 18" $BATS_TMPDIR/result
}
