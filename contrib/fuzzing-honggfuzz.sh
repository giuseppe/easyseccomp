#!/bin/sh

set -euxo pipefail

./configure CC=hfuzz-clang CPPFLAGS="-DFUZZER"
make clean
make -j $(nproc)
EASYSECCOMP_FUZZ=1 honggfuzz --timeout=10 -i contrib/testcases --  ./easyseccomp
