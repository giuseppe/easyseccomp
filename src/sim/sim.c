/*
 * easyseccomp
 *
 * Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
 * easyseccomp is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * easyseccomp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with easyseccomp.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <unistd.h>

/* libseccomp is used to resolve syscall names.  */
#include <seccomp.h>

#include "bpf.h"

/* Copied from crun for read_all_fd.  */
#define LIKELY(x) __builtin_expect ((x), 1)
#define UNLIKELY(x) __builtin_expect ((x), 0)

#ifndef TEMP_FAILURE_RETRY
#  define TEMP_FAILURE_RETRY(expression)      \
    (__extension__({                          \
      long int __result;                      \
      do                                      \
        __result = (long int) (expression);   \
      while (__result < 0 && errno == EINTR); \
      __result;                               \
    }))
#endif

static void
OOM()
{
  error (EXIT_FAILURE, ENOMEM, "OOM");
}

static void *
xmalloc (size_t size)
{
  void *res = malloc (size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

static void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

void
read_all_fd (int fd, const char *description, u_char **out, size_t *len)
{
  int ret;
  size_t nread, allocated;
  off_t size = 0;
  u_char *buf = NULL;

  ret = 4096;

  /* NUL terminate the buffer.  */
  allocated = size;
  if (size == 0)
    allocated = 4096;
  buf = xmalloc (allocated + 1);
  nread = 0;
  while ((size && nread < (size_t) size) || size == 0)
    {
      ret = TEMP_FAILURE_RETRY (read (fd, buf + nread, allocated - nread));
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, errno, "error reading from file `%s`", description);

      if (ret == 0)
        break;

      nread += ret;

      allocated += 4096;
      buf = xrealloc (buf, allocated + 1);
    }
  buf[nread] = '\0';
  *out = buf;
  buf = NULL;
  if (len)
    *len = nread;
}

unsigned int arc4random ()
{
  return random ();
}

static int
resolve_syscall (const char *name)
{
  char *endptr = NULL;
  int syscall;

  errno = 0;
  syscall = strtol (name, &endptr, 10);
  if (errno == 0 && *endptr == '\0')
    return syscall;

  syscall = seccomp_syscall_resolve_name (name);
  if (syscall == __NR_SCMP_ERROR)
    error (EXIT_FAILURE, 0, "unknown syscall `%s`", name);

  return syscall;
}

static int
resolve_arch (const char *name)
{
  char *endptr = NULL;
  int arch;

  errno = 0;
  arch = strtol (name, &endptr, 10);
  if (errno == 0 && *endptr == '\0')
    return arch;

  arch = seccomp_arch_resolve_name (name);
  if (arch == 0)
    error (EXIT_FAILURE, 0, "unknown arch `%s`", name);

  return arch;
}

u_int bpf_filter (const struct bpf_insn *pc, const u_char *pkt,
                  u_int wirelen, u_int buflen);

int bpf_validate(struct bpf_insn *f, int len);

const char *get_seccomp_action (u_int ret, int *errno_code)
{
  u_int action;

  *errno_code = 0;

  action = ret & SECCOMP_RET_ACTION;

  if (action == SECCOMP_RET_ALLOW)
    return "SECCOMP_RET_ALLOW";

#ifdef SECCOMP_RET_TRAP
  if (action == SECCOMP_RET_TRAP)
    return "SECCOMP_RET_TRAP";
#endif

#ifdef SECCOMP_RET_USER_NOTIF
  if (action == SECCOMP_RET_USER_NOTIF)
    return "SECCOMP_RET_USER_NOTIF";
#endif

#ifdef SECCOMP_RET_KILL
  if (action == SECCOMP_RET_KILL)
    return "SECCOMP_RET_KILL";
#endif

#ifdef SECCOMP_RET_KILL_THREAD
  if (action == SECCOMP_RET_KILL_THREAD)
    return "SECCOMP_RET_KILL_THREAD";
#endif

#ifdef SECCOMP_RET_KILL_PROCESS
  if (action == SECCOMP_RET_KILL_PROCESS)
    return "SECCOMP_RET_KILL_PROCESS";
#endif

  /* From here there are listed the actions that use
     an errno value.  */

  *errno_code = ret & 0xFFFF;

#ifdef SECCOMP_RET_ERRNO
  if (action == SECCOMP_RET_ERRNO)
    return "SECCOMP_RET_ERRNO";
#endif

#ifdef SECCOMP_RET_TRACE
  if (action == SECCOMP_RET_TRACE)
    return "SECCOMP_RET_TRACE";
#endif

  error (EXIT_FAILURE, 0, "invalid return code");
  return NULL;
}

int main (int argc, char **argv)
{
  struct seccomp_data data;
  struct bpf_insn *program;
  size_t size;
  int len, i, ret, errno_code = 0;
  u_int filter_res = 0;
  const char *action = NULL;

  if (argc < 3)
    {
      error (0, 0, "not enough parameters passed");
      if (argc > 0)
        error (0, 0, "USAGE: %s SYSCALL_NUMBER ARCH ARGS...", argv[0]);
      exit (EXIT_FAILURE);
    }

  memset (&data, 0, sizeof (data));

  data.nr = resolve_syscall (argv[1]);
  data.arch = resolve_arch (argv[2]);
  data.instruction_pointer = 0x0;
  for (i = 0; i < 6; i++)
    data.args[i] = (3 + i < argc) ? atoi (argv[3 + i]) : 0;

  read_all_fd (0, "stdin", (u_char **) &program, &size);

  len = size / sizeof (struct bpf_insn);

  ret = bpf_validate (program, len);
  if (ret == 0)
    error (EXIT_FAILURE, 0, "invalid program");

  filter_res = bpf_filter (program,
                           (u_char *) &data,
                           sizeof (data),
                           sizeof (data));
  action = get_seccomp_action (filter_res, &errno_code);
  printf ("raw: %u\naction: %s\nerrno: %d\n", filter_res, action, errno_code);
  free (program);
  return 0;
}
