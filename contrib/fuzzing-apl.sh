#!/bin/sh

set -euxo pipefail

./configure CC=afl-gcc AFL_USE_ASAN=1
make -j $(nproc)
AFL_SKIP_CPUFREQ=1 ASAN_OPTIONS='abort_on_error=1:symbolize=0:detect_leaks=1' AFL_USE_ASAN=1 afl-fuzz -d -i contrib/testcases -o /tmp/findings/ ./easyseccomp -i @@ -o /dev/null
