#!/bin/sh

set -euxo pipefail

./configure CC=hfuzz-cc
honggfuzz -i contrib/testcases --  ./easyseccomp -i ___FILE___ -o /dev/null
