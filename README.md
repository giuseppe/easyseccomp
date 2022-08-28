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

# Language

The policy is a list of `CONDITION => STATEMENT;` rules that are
executed in the specified order.
The program terminates performing the action specified `STATEMENT`
for the first `CONDITION` that is true.

If the `CONDITION` is not specified (`=> STATEMENT();`), then the
`STATEMENT` is always performed.

## Supported variables

| Name       | Description                 |
|------------|-----------------------------|
| `$syscall` | The syscall number          |
| `$arch`    | Architecture                |
| `$arg0`    | 1st argument to the syscall |
| `$arg1`    | 2nd argument to the syscall |
| `$arg2`    | 3rd argument to the syscall |
| `$arg3`    | 4th argument to the syscall |
| `$arg4`    | 5th argument to the syscall |
| `$arg5`    | 6th argument to the syscall |

## Actions

| Name             | Description                                           |
|------------------|-------------------------------------------------------|
| `ALLOW()`        | Allow the syscall                                     |
| `TRAP()`         | Trap the syscall                                      |
| `NOTIFY()`       | Handle the syscall through a user space handler       |
| `LOG()`          | Log the syscall                                       |
| `KILL()`         | Kill the process                                      |
| `KILL_PROCESS()` | Kill the process                                      |
| `KILL_THREAD()`  | Kill the thread                                       |
| `ERRNO(ERRNO)`   | Return the specified error code                       |
| `TRACE(ERRNO)`   | Trace the syscall and return the error specified code |


## Comparison Operators

| Name                          | Description                                         |
|-------------------------------|-----------------------------------------------------|
| `$variable == VALUE`          | Equality                                            |
| `$variable != VALUE`          | Disequality                                         |
| `$variable < VALUE`           | Less than                                           |
| `$variable <= VALUE`          | Less than or equal                                  |
| `$variable > VALUE`           | Greater than                                        |
| `$variable >= VALUE`          | Greater than or equal                               |
| `$variable & MASK == VALUE`   | Bitwise AND                                         |
| `$variable in (SET)`          | The variable value is part of SET                   |
| `$variable not in (SET)`      | The variable value is not part of SET               |
| `$syscall in KERNEL(VERSION)` | The syscall is part of the specified kernel version |

## Lookups

When the variable `$syscall` is used the value can be specified in the
form `@name` and `name` refers to a syscall name that is looked up
using the current architecture.

It is possible to force the lookup for a specific architecture using
the format `@name@arch`

# Directives

It is possible to define some rules that are conditionally included in
the final BPF:

```
#ifdef DIRECTIVE_NAME
# ifdef ANOTHER_DIRECTIVE
=> ALLOW();
# endif
#endif
```

The rules included between the `#ifdef` and the `#endif` are included
only if both `DIRECTIVE_NAME` and `ANOTHER_DIRECTIVE` are specified at
compile time.

It enables writing conditional policies such as:

```
#ifndef CAP_AUDIT_WRITE
$syscall == @socket && $arg0 == 16 && $arg2 == 9 => ERRNO(EINVAL);
#endif

$syscall == @socket => ALLOW();
```

A higher level tool, such as a container engine, can specify different
profiles,  In the example above it specifies whether a capability is
not added to a container and define a different rule for handling the
`socket` syscall.

## Examples

- `=> ALLOW();`: Allow the syscall.
- `$syscall in (@read, @write) => ALLOW();`: The syscall is one of `read` or `write`.
- `$syscall not in (4, 5) => ALLOW();`: The syscall value is not included in the set `(4, 5)`.
- `$syscall == @read && $arg0 == 2 => ALLOW();` The syscall is `read` and the first argument is `2`.
- `$syscall ==@write && $arg0 > 2 => ALLOW();`: Write to a fd bigger than 2.
- `$syscall == @renameat2@aarch64 => ALLOW();`:  The syscall is value `renameat2` as
defined for the `aarch64` architecture.
- `$syscall in KERNEL(5.3)`: The syscall is present in the kernel 5.3

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

