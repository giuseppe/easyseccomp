#!/usr/bin/env python
from pkg_resources import parse_version
import glob
import sys
import os
try:
    import seccomp
except ImportError:
    import pyseccomp as seccomp

if len(sys.argv) == 1:
    raise ValueError("specify a data directory")

d = sys.argv[1]

def normalize(version):
    version = parse_version(version).release
    if len(version) == 1:
        return version + (0, 0, 0,)
    if len(version) == 2:
        return version + (0, 0,)
    if len(version) == 3:
        return version + (0,)
    if len(version) != 4:
        raise ValueError("invalid version %s" % version)
    return version

def get_version_value(version):
    version = normalize(version)
    ret = 0
    for i in version:
        ret = (ret << 8) | i
    return ret

def exist(syscall):
    for i in [seccomp.Arch.AARCH64,
              seccomp.Arch.ARM,
              seccomp.Arch.MIPS,
              seccomp.Arch.MIPS64,
              seccomp.Arch.MIPS64N32,
              seccomp.Arch.MIPSEL,
              seccomp.Arch.MIPSEL64,
              seccomp.Arch.MIPSEL64N32,
              seccomp.Arch.NATIVE,
              seccomp.Arch.PARISC,
              seccomp.Arch.PARISC64,
              seccomp.Arch.PPC,
              seccomp.Arch.PPC64,
              seccomp.Arch.PPC64LE,
              seccomp.Arch.RISCV64,
              seccomp.Arch.S390,
              seccomp.Arch.S390X,
              seccomp.Arch.X32,
              seccomp.Arch.X86,
              seccomp.Arch.X86_64]:
        if seccomp.resolve_syscall(i, syscall) != -1:
            return True
    return False

syscalls = {}
for path in glob.glob("%s/v*" % d):
    ver = os.path.basename(path)
    with open(path) as f:
        for syscall in f:
            syscall = syscall.strip()
            if not exist(syscall):
                continue
            if syscall not in syscalls:
                syscalls[syscall.strip()] = ver
            # Take the oldest version
            elif parse_version(syscalls[syscall]) > parse_version(ver):
                syscalls[syscall] = ver

print("const char *\nkernel_syscalls[] =\n{")
for k, v in syscalls.items():
    print("    \"%s\", /* %s */" % (k, v))
print("    0\n};\n")

print("const int\nkernel_version_for_syscalls[] =\n{")
for _, v in syscalls.items():
    print("    %s, /* %s */" % (get_version_value(v), v))
print("    0\n};")

