/*
 * easyseccomp
 *
 * Copyright (C) 2022, 2024 Giuseppe Scrivano <giuseppe@scrivano.org>
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

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/mman.h>

#ifndef SECCOMP_SET_MODE_FILTER
#  define SECCOMP_SET_MODE_FILTER 1
#endif

static int
syscall_seccomp (unsigned int operation, unsigned int flags, void *args)
{
  return (int) syscall (__NR_seccomp, operation, flags, args);
}

int
main (int argc, char *argv[])
{
  struct sock_fprog seccomp_filter;
  void *addr = NULL;
  struct stat st;
  size_t size;
  int fd;
  int r;

  if (argc < 3)
    error (EXIT_FAILURE, 0, "usage: %s seccomp.bpf COMMAND ...", argv[0]);

  fd = open (argv[1], O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "open `%s`", argv[1]);

  r = fstat (fd, &st);
  if (r < 0)
    error (EXIT_FAILURE, errno, "fstat `%s", argv[1]);

  if (st.st_size > 0)
    {
      addr = mmap (NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
      if (addr == MAP_FAILED)
        error (EXIT_FAILURE, errno, "mmap");
      size = st.st_size;
    }
  else
    {
      size = 0;
      for (;;)
        {
          addr = realloc (addr, size + 4096);
          if (addr == NULL)
            error (EXIT_FAILURE, errno, "malloc");

          do
            r = read (fd, addr + size, 4096);
          while (r < 0 && errno == EINTR);
          if (r < 0)
            error (EXIT_FAILURE, errno, "read");
          if (r == 0)
            break;
          size += r;
        }
    }
  seccomp_filter.len = size / 8;
  seccomp_filter.filter = (struct sock_filter *) addr;

  r = syscall_seccomp (SECCOMP_SET_MODE_FILTER, 0, &seccomp_filter);
  if (r < 0)
    {
      r = prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
      if (r == 0)
        r = syscall_seccomp (SECCOMP_SET_MODE_FILTER, 0, &seccomp_filter);
      if (r < 0)
        error (EXIT_FAILURE, errno, "seccomp");
    }

  if (st.st_size == 0)
    free (addr);
  else
    {
      r = munmap (addr, st.st_size);
      if (r < 0)
        error (EXIT_FAILURE, errno, "munmap");
    }

  for (argc = 2; argv[argc]; argc++)
    argv[argc - 2] = argv[argc];
  argv[argc - 2] = NULL;

  execvp (argv[0], argv);
  exit (EXIT_FAILURE);
}
