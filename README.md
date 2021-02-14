# easyseccomp

a domain specific language for defining seccomp profiles for
containers in an easier way and having more control on the generated
BPF that it is possible with libseccomp.  This blog post explains more
in detail why the project was started:
https://www.scrivano.org/posts/2021-01-30-easyseccomp/

A seccomp profile can be defined as:

```
// Native support for comments without abusing JSON!

#ifdef DENY_MKDIR_WITH_EINVAL
$syscall in (@mkdir) => ERRNO(EINVAL);
#endif

#ifndef DENY_MKDIR_WITH_EINVAL
$syscall in (@mkdir) => ERRNO(EPERM);
#endif

=> ALLOW();
```

and generate the raw BPF as:

```sh
$ easyseccomp < profile.seccomp > seccomp.bpf
$ easyseccomp -d DENY_MKDIR_WITH_EINVAL < profile.seccomp > seccomp.bpf
```

# Dependencies for OCI containers

it currently requires this feature in crun: https://github.com/containers/crun/pull/578

It enables to load a custom raw bpf filter instead of the seccomp
configuration specified in the container configuration file.

With that feature in crun, it is possible to create a container using
the seccomp profile as:

```sh
$ easyseccomp < profile.seccomp > seccomp.bpf
$ podman run --annotation run.oci.seccomp_bpf_file=/tmp/seccomp.bpf --rm fedora mkdir /tmp/foo
mkdir: cannot create directory '/tmp/foo': Operation not permitted

$ easyseccomp DENY_MKDIR_WITH_EINVAL < profile.seccomp > seccomp.bpf
$ podman run --annotation run.oci.seccomp_bpf_file=/tmp/seccomp.bpf --rm fedora mkdir /tmp/foo
mkdir: cannot create directory '/tmp/foo': Invalid argument
```

# BPF generator

easyseccomp uses libseccomp only for the syscall number lookup.  It is
not used for generating the bpf bytecode as libseccomp internally
rewrites the rules.

