# -*- mode: sh -*-

function setup {
    if $(test $(uname -m) != x86_64); then
        skip "tests assume x86_64"
    fi
}
