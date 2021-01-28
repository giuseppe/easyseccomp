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
#define __USE_GNU 1
#define _GNU_SOURCE 1

#include "generator.h"
#include "errnos.h"
#include "error.h"
#include <stdio.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <stddef.h>

/* libseccomp is used to resolve syscall names.  */
#include <seccomp.h>

#define STREQ(a,b) (strcmp (a,b) == 0)

#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define syscall_arch (offsetof(struct seccomp_data, arch))

enum
  {
    VARIABLE_TYPE_ARCH = 1,
    VARIABLE_TYPE_SYSCALL = 2,
    VARIABLE_TYPE_ARG = 3,
  };

struct define_s
{
  struct define_s *next;
  const char *value;
};

struct define_s *defines;

static int
is_defined (const char *name)
{
  struct define_s *it;

  for (it = defines; it; it = it->next)
    {
      if (STREQ (it->value, name))
        return 1;
    }
  return 0;
}

void
define (const char *v)
{
  struct define_s *d;

  d = xmalloc0 (sizeof (struct define_s));
  d->next = defines;
  d->value = v;
  defines = d;
}

static void
emit (struct sock_filter *filter, size_t len)
{
  if (fwrite (filter, 1, len, stdout) != len)
    abort ();
}

static int
load_variable (const char *name)
{
  int offset = -1;
  int type = 0;

  if (STREQ (name, "$arch"))
    {
      offset = syscall_arch;
      type = VARIABLE_TYPE_ARCH;
    }
  else if (STREQ (name, "$syscall"))
    {
      offset = syscall_nr;
      type = VARIABLE_TYPE_SYSCALL;
    }
  else if (STREQ (name, "$arg0"))
    {
      offset = syscall_arg (0);
      type = VARIABLE_TYPE_ARG;
    }
  else if (STREQ (name, "$arg1"))
    {
      offset = syscall_arg (1);
      type = VARIABLE_TYPE_ARG;
    }
  else if (STREQ (name, "$arg2"))
    {
      offset = syscall_arg (2);
      type = VARIABLE_TYPE_ARG;
    }
  else if (STREQ (name, "$arg3"))
    {
      offset = syscall_arg (3);
      type = VARIABLE_TYPE_ARG;
    }
  else if (STREQ (name, "$arg4"))
    {
      offset = syscall_arg (4);
      type = VARIABLE_TYPE_ARG;
    }
  else if (STREQ (name, "$arg5"))
    {
      offset = syscall_arg (5);
      type = VARIABLE_TYPE_ARG;
    }
  else
    {
      error (EXIT_FAILURE, 0, "unknown variable `%s`", name);
    }

  {
    struct sock_filter stmt[] =
      {
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS, offset)
      };
    emit (stmt, sizeof (struct sock_filter));
  }

  return type;
}

static int
get_errno (struct action_s *a)
{
  size_t i;

  if (a->str_value == NULL)
    return a->int_value;

  for (i = 0; errnos[i].name; i++)
    if (STREQ (a->str_value, errnos[i].name))
      return errnos[i].value;

  error (EXIT_FAILURE, 0, "unknown errno value `%s`", a->str_value);
}

static void
generate_action (struct action_s *a)
{
  if (STREQ (a->name, "ALLOW"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "TRAP"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_TRAP)
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "NOTIFY"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF)
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "LOG"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_LOG)
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "KILL"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_KILL)
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "KILL_THREAD"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_KILL_THREAD)
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "KILL_PROCESS"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS)
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "ERRNO"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_ERRNO|get_errno (a))
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else if (STREQ (a->name, "TRACE"))
    {
      struct sock_filter stmt[] = {
        BPF_STMT (BPF_RET|BPF_K, SECCOMP_RET_TRACE|get_errno (a))
      };
      emit (stmt, sizeof (struct sock_filter));
    }
  else
    error (EXIT_FAILURE, 0, "unknown action `%s`", a->name);
}

static int
resolve_syscall (const char *name)
{
  int syscall;

  if (name[0] == '@')
    name++;

  syscall = seccomp_syscall_resolve_name (name);
  if (syscall == __NR_SCMP_ERROR)
    error (EXIT_FAILURE, 0, "unknown syscall `%s`", name);

  return syscall;
}

static int
resolve_arch (const char *name)
{
  int arch;

  if (name[0] == '@')
    name++;

  arch = seccomp_arch_resolve_name (name);
  if (arch == 0)
    error (EXIT_FAILURE, 0, "unknown arch `%s`", name);

  return arch;
}

static int
read_value (struct value_s *v, int type)
{
  if (v->name == NULL)
    return v->value;

  switch (type)
    {
    case VARIABLE_TYPE_ARCH:
      return resolve_arch (v->name);

    case VARIABLE_TYPE_SYSCALL:
      return resolve_syscall (v->name);

    case VARIABLE_TYPE_ARG:
    default:
      error (EXIT_FAILURE, 0, "unknown argument `%s`", v->name);
    }

}

static void
generate_masked_condition (struct condition_s *c, int jump_len)
{
  int type;
  int value;
  int mask_value;

  type = load_variable (c->name);

  value = read_value (c->value, type);
  mask_value = read_value (c->mask, type);

  {
    struct sock_filter stmt[] = {
      BPF_STMT(BPF_ALU|BPF_AND|BPF_IMM, mask_value),
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, value, 0, jump_len),
    };
    emit (stmt, sizeof (stmt));
  }
}

static void
generate_simple_condition (struct condition_s *c, int jump_len)
{
  int type;
  int jt = 0;
  int jf = 0;
  int value;
  int mask;

  type = load_variable (c->name);
  switch (c->type)
    {
    case TYPE_EQ:
      mask = BPF_JEQ;
      jf = jump_len;
      break;

    case TYPE_NE:
      mask = BPF_JEQ;
      jt = jump_len;
      break;

    case TYPE_GT:
      mask = BPF_JGT;
      jf = jump_len;
      break;

    case TYPE_GE:
      mask = BPF_JGE;
      jf = jump_len;
      break;

    case TYPE_LT:
      mask = BPF_JGE;
      jt = jump_len;
      break;

    case TYPE_LE:
      mask = BPF_JGT;
      jt = jump_len;
      break;

    default:
      error (EXIT_FAILURE, 0, "invalid condition type %d", c->type);
    }

  value = read_value (c->value, type);

  struct sock_filter stmt[] = {
    BPF_JUMP(BPF_JMP|mask|BPF_K, value, jt, jf),
  };
  emit (stmt, sizeof (struct sock_filter));
}

static void
linearize_and_conditions (struct condition_s *it, struct condition_s **conditions, size_t *so_far, size_t max)
{
  if (it->type == TYPE_AND)
    {
      linearize_and_conditions (it->and_l, conditions, so_far, max);
      linearize_and_conditions (it->and_r, conditions, so_far, max);
      return;
    }
  if (*so_far == max - 1)
    error (EXIT_FAILURE, 0, "AND condition too long");

  if (it->type == TYPE_IN_SET || it->type == TYPE_MASKED_EQ)
    error (EXIT_FAILURE, 0, "complex conditions not supported with AND");
  
  conditions[*so_far] = it;
  (*so_far)++;
}

static void
generate_and_condition_action (struct condition_s *c, struct action_s *a)
{
  const int MAX = 8;
  struct condition_s *conditions[MAX];
  size_t i, so_far = 0;

  linearize_and_conditions (c, conditions, &so_far, MAX);
  for (i = 0; i < so_far; i++)
    generate_simple_condition (conditions[i], 1 + 2 * (so_far - 1 - i));
  generate_action (a);
}

static void
generate_condition_and_action (struct condition_s *c, struct action_s *a)
{
  if (c == NULL)
    return;

  switch (c->type)
    {
    case TYPE_IN_SET:
      {
        struct condition_s tmp_condition;
        struct value_s tmp_value;
        struct head_s *set;

        /* This must be implemented using ranges, but for now
           convert to a series of equalities.  */
        memset (&tmp_condition, 0, sizeof (tmp_condition));
        tmp_condition.type = TYPE_EQ;
        tmp_condition.name = c->name;
        for (set = c->set; set; set = set->next)
          {
            tmp_condition.value = set->value;
            generate_simple_condition (&tmp_condition, 1);
            generate_action (a);
          }
      }
      break;

    case TYPE_AND:
      generate_and_condition_action (c, a);
      break;

    case TYPE_EQ:
    case TYPE_NE:
    case TYPE_LT:
    case TYPE_LE:
    case TYPE_GT:
    case TYPE_GE:
      generate_simple_condition (c, 1);
      generate_action (a);
      break;

    case TYPE_MASKED_EQ:
      generate_masked_condition (c, 1);
      generate_action (a);
      break;

    default:
      error (EXIT_FAILURE, 0, "invalid condition type %d", c->type);
      break;
    }
}

static struct rule_s *
skip_directive (struct rule_s * it)
{
  int to_skip = 1;
  for (it = it->next; it; it = it->next)
    {
      if (it->directive_name == NULL)
        continue;

      if (STREQ (it->directive_name, "ifdef") || STREQ (it->directive_name, "ifndef"))
        {
          to_skip++;
        }
      else if (STREQ (it->directive_name, "endif"))
        {
          to_skip--;
          if (to_skip == 0)
            break;
        }
    }

  if (it == NULL)
    error (EXIT_FAILURE, 0, "directive `#%s` not ended", it->directive_name);

  return it;
}

void
handle (struct rule_s *rules)
{
  struct rule_s *it;
  int directive_recursion = 0;

  for (it = rules; it; it = it->next)
    {
      if (it->directive_name)
        {
          int ifdef = 0;

          ifdef = STREQ (it->directive_name, "ifdef");
          if (ifdef || STREQ (it->directive_name, "ifndef"))
            {
              if (it->directive_value == NULL)
                error (EXIT_FAILURE, 0, "invalid directive `#%s`", it->directive_name);

              /* Check if the directive value is set.  */
              if (ifdef == is_defined (it->directive_value))
                directive_recursion++;
              else
                it = skip_directive (it);
            }
          else if (STREQ (it->directive_name, "endif"))
            {
              if (directive_recursion == 0)
                error (EXIT_FAILURE, 0, "invalid directive `#%s`", it->directive_name);

              directive_recursion--;
            }
          else
            error (EXIT_FAILURE, 0, "unknown directive `#%s`", it->directive_name);

          continue;
        }

      if (it->condition)
        generate_condition_and_action (it->condition, it->action);
      else
        generate_action (it->action);
    }
}
