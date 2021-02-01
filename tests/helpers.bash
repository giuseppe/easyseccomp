# -*- mode: sh -*-

function setup {
    ID=$(head -c 32 /dev/urandom | sha256sum | cut -f 1 -d ' ')
    PROGRAM=$BATS_TMPDIR/program-$ID
    BPF=$BATS_TMPDIR/bpf-$ID
    RESULT=$BATS_TMPDIR/result-$ID

    if $(test $(uname -m) != x86_64); then
        skip "tests assume x86_64"
    fi
}
