#!/usr/bin/env -S bats
# -*- mode: sh -*-

load helpers

@test "test arches" {
    cat > $PROGRAM <<EOF
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
    easyseccomp < $PROGRAM > $BPF

    sim mkdir x86 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    sim mkdir x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 2" $RESULT

    sim mkdir x32 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 3" $RESULT

    sim mkdir arm 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 4" $RESULT

    sim mkdir aarch64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 5" $RESULT

    sim mkdir mips 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 6" $RESULT

    sim mkdir mipsel 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 7" $RESULT

    sim mkdir mips64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 8" $RESULT

    sim mkdir mipsel64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 9" $RESULT

    sim mkdir mips64n32 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 10" $RESULT

    sim mkdir mipsel64n32 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 11" $RESULT

    sim mkdir parisc 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 12" $RESULT

    sim mkdir parisc64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 13" $RESULT

    sim mkdir ppc 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 14" $RESULT

    sim mkdir ppc64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 15" $RESULT

    sim mkdir ppc64le 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 16" $RESULT

    sim mkdir s390 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 17" $RESULT

    sim mkdir s390x 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 18" $RESULT
}

@test "test syscall@arch" {
    cat > $PROGRAM <<EOF
\$arch == @x86_64 && \$syscall == @close@x86_64  => ERRNO(1);
\$arch == @mipsel && \$syscall == @close@x86_64  => ERRNO(2);
=> ALLOW();
EOF
    easyseccomp < $PROGRAM > $BPF

    sim close x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 1" $RESULT

    sim close mipsel 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ERRNO $RESULT
    grep "errno: 2" $RESULT

    sim read x86_64 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT

    sim read mipsel 0 0 0 0 0 0 < $BPF > $RESULT
    grep SECCOMP_RET_ALLOW $RESULT
    grep "errno: 0" $RESULT
}
