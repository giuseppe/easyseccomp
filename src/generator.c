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
#include "syscall-versions/syscall-versions.h"
#include "errnos.h"
#include "error.h"
#include "libeasyseccomp_a-parser.h"
#include "libeasyseccomp_a-lexer.h"
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>


/* libseccomp is used to resolve syscall names.  */
#include <seccomp.h>

#define cleanup_free __attribute__ ((cleanup (cleanup_freep)))

#define min(a, b) ((a < b) ? a : b)

#define STREQ(a,b) (strcmp (a,b) == 0)

#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define syscall_arch (offsetof(struct seccomp_data, arch))

#define VARIABLE_TYPE(x) ((x >> 8) & 0xFF)
#define VARIABLE_OFFSET(x) (x & 0xFF)
#define MAKE_VARIABLE(t,i) ((t << 8) | (i & 0xFF))

struct define_s
{
  struct define_s *next;
  char *value;
};

struct easy_seccomp_ctx_s
{
  struct define_s *defines;
  char *error;
  struct rule_s *rules;
  FILE *out;
  bool verbose;
};

struct easy_seccomp_ctx_s *
easy_seccomp_make_ctx()
{
  return calloc (1, sizeof (struct easy_seccomp_ctx_s));
}

void
easy_seccomp_set_parser_rules (struct easy_seccomp_ctx_s *ctx, struct rule_s *rules)
{
  free_rules (ctx->rules);
  ctx->rules = rules;
}

void
easy_seccomp_free_ctx (struct easy_seccomp_ctx_s *ctx)
{
  struct define_s *it = ctx->defines;

  while (it)
    {
      struct define_s *n = it->next;

      free (it->value);

      n = it->next;
      free (it);
      it = n;
    }

  free_rules (ctx->rules);
  free (ctx->error);
  free (ctx);
}

void
easy_seccomp_set_error (struct easy_seccomp_ctx_s *ctx, const char *fmt, ...)
{
  va_list args_list;
  char *msg = NULL;

  va_start (args_list, fmt);

  if (vasprintf (&msg, fmt, args_list) < 0)
    {
      va_end (args_list);
      free (ctx->error);
      ctx->error = xstrdup ("internal error");
    }

  va_end (args_list);

  free (ctx->error);
  ctx->error = msg;
}


const char *
easy_seccomp_get_last_error (struct easy_seccomp_ctx_s *ctx)
{
  return ctx->error;
}

bool
easy_seccomp_get_verbose (struct easy_seccomp_ctx_s *ctx)
{
  return ctx->verbose;
}

void
easy_seccomp_set_verbose (struct easy_seccomp_ctx_s *ctx, bool verbose)
{
  ctx->verbose = verbose;
}

enum
  {
    VARIABLE_TYPE_ARCH = 1,
    VARIABLE_TYPE_SYSCALL = 2,
    VARIABLE_TYPE_ARG = 3,
  };

static void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

static int
is_defined (struct easy_seccomp_ctx_s *ctx, const char *name)
{
  struct define_s *it;

  for (it = ctx->defines; it; it = it->next)
    {
      if (STREQ (it->value, name))
        return 1;
    }
  return 0;
}

void
easy_seccomp_define (struct easy_seccomp_ctx_s *ctx, const char *v)
{
  struct define_s *d;

  d = xmalloc0 (sizeof (struct define_s));
  d->next = ctx->defines;
  d->value = xstrdup (v);
  ctx->defines = d;
}

static const char *
drop_prefix (const char *v, char p)
{
  if (v[0] == p)
    return v + 1;
  return v;
}

static int
emit (struct easy_seccomp_ctx_s *ctx, struct sock_filter *filter, size_t len)
{
  if (fwrite (filter, 1, len, ctx->out) != len)
    {
      easy_seccomp_set_error (ctx, "failed to write to the destination");
      return -1;
    }
  return 0;
}

static int
emit_stmt (struct easy_seccomp_ctx_s *ctx, int code, int k)
{
  struct sock_filter stmt[] = {
    BPF_STMT (code, k)
  };
  return emit (ctx, stmt, sizeof (stmt[0]));
}

static bool
multiplexed_syscall_p (int variable, int value)
{
  if (VARIABLE_TYPE (variable) != VARIABLE_TYPE_SYSCALL)
    return false;

  return value < 0;
}

static void
multiplexed_syscall_ignored_warning (struct easy_seccomp_ctx_s *ctx, struct value_s *v)
{
  if (! ctx->verbose)
    return;

  if (v->name)
    fprintf (stderr, "ignoring multiplexed syscall `%s`\n", drop_prefix (v->name, '@'));
  else
    fprintf (stderr, "ignoring multiplexed syscall `%d`\n", v->value);
}

static struct head_s *
calculate_set_from_kernel_version (struct easy_seccomp_ctx_s *ctx, const char *version)
{
  char *endptr = NULL;
  struct head_s *h = NULL;
  int parts = 0, i, tmp, value = 0;

  if (strlen (version) < 10)
    {
      easy_seccomp_set_error (ctx, "invalid kernel version");
      return NULL;
    }

  version += strlen ("KERNEL(");
  while (*version)
    {
      if (parts++ > 4)
        {
          easy_seccomp_set_error (ctx, "invalid kernel version");
          return NULL;
        }

      tmp = strtol (version, &endptr, 10);

      value = (value << 8) | tmp;

      if (*endptr == '.')
        endptr++;
      if (*endptr == ')')
        break;

      version = endptr;
    }
  while (parts++ < 4)
    value <<= 8;

  for (i = 0; kernel_syscalls[i]; i++)
    {
      if (kernel_version_for_syscalls[i] <= value)
        {
          struct value_s *v;

          v = make_value_from_name (xstrdup (kernel_syscalls[i]));
          h = make_set (v, h);
        }
    }

  return h;
}

static int
load_variable (struct easy_seccomp_ctx_s *ctx, const char *name)
{
  int offset = 0;
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
      easy_seccomp_set_error (ctx, "unknown variable `%s`", name);
      return -1;
    }

  return MAKE_VARIABLE (type, offset);
}

static int
emit_load (struct easy_seccomp_ctx_s *ctx, int what)
{
  int offset = VARIABLE_OFFSET (what);

  switch (VARIABLE_TYPE (what))
    {
    case VARIABLE_TYPE_ARCH:
      break;

    case VARIABLE_TYPE_SYSCALL:
      break;

    case VARIABLE_TYPE_ARG:
      break;

    default:
      easy_seccomp_set_error (ctx, "unknown variable type `%d`", VARIABLE_TYPE (what));
      return -1;
    }

  emit_stmt (ctx, BPF_LD|BPF_W|BPF_ABS, offset);
  return 0;
}

static int
get_errno (struct easy_seccomp_ctx_s *ctx, struct action_s *a)
{
  size_t i;

  if (a->str_value == NULL)
    return a->int_value;

  for (i = 0; errnos[i].name; i++)
    if (STREQ (a->str_value, errnos[i].name))
      return errnos[i].value;

  easy_seccomp_set_error (ctx, "unknown errno value `%s`", a->str_value);
  return -1;
}

static int
generate_action (struct easy_seccomp_ctx_s *ctx, struct action_s *a)
{
  if (STREQ (a->name, "ALLOW"))
    emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_ALLOW);
  else if (STREQ (a->name, "TRAP"))
    emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_TRAP);
  else if (STREQ (a->name, "NOTIFY"))
    emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF);
  else if (STREQ (a->name, "LOG"))
    emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_LOG);
  else if (STREQ (a->name, "KILL"))
    emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_KILL);
  else if (STREQ (a->name, "KILL_THREAD"))
    emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_KILL_THREAD);
  else if (STREQ (a->name, "KILL_PROCESS"))
    emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS);
  else if (STREQ (a->name, "ERRNO"))
    {
      int e = get_errno (ctx, a);
      if (e < 0)
        return e;
      emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_ERRNO|e);
    }
  else if (STREQ (a->name, "TRACE"))
    {
      int e = get_errno (ctx, a);
      if (e < 0)
        return e;
      emit_stmt (ctx, BPF_RET|BPF_K, SECCOMP_RET_TRACE|e);
    }
  else
    {
      easy_seccomp_set_error (ctx, "unknown action `%s`", a->name);
      return -1;
    }
  return 0;
}

static int
resolve_arch (struct easy_seccomp_ctx_s *ctx, const char *name, int *arch)
{
  name = drop_prefix (name, '@');

  *arch = seccomp_arch_resolve_name (name);
  if (*arch == 0)
    {
      easy_seccomp_set_error (ctx, "unknown arch `%s`", name);
      return -1;
    }

  return 0;
}

static int
resolve_syscall (struct easy_seccomp_ctx_s *ctx, const char *name, int *syscall)
{
  char buf[1024];
  char *arch_sep;

  name = drop_prefix (name, '@');

  if (strlen (name) > sizeof (buf) -1)
    {
      easy_seccomp_set_error (ctx, "invalid syscall `%s`", name);
      return -1;
    }

  strcpy (buf, name);

  arch_sep = strchr (name, '@');
  if (arch_sep == NULL)
    *syscall = seccomp_syscall_resolve_name (name);
  else
    {
      int ret, arch_token;

      *arch_sep = '\0';

      ret = resolve_arch (ctx, arch_sep + 1, &arch_token);
      if (ret < 0)
        return ret;

      *syscall = seccomp_syscall_resolve_name_arch (arch_token, name);
    }

  if (*syscall == __NR_SCMP_ERROR)
    {
      easy_seccomp_set_error (ctx, "unknown syscall `%s`", name);
      return -1;
    }

  return 0;
}

static int
read_value (struct easy_seccomp_ctx_s *ctx, struct value_s *v, int variable, int *out)
{
  if (v->name == NULL)
    {
      *out = v->value;
      return 0;
    }

  switch (VARIABLE_TYPE (variable))
    {
    case VARIABLE_TYPE_ARCH:
      return resolve_arch (ctx, v->name, out);

    case VARIABLE_TYPE_SYSCALL:
      return resolve_syscall (ctx, v->name, out);

    case VARIABLE_TYPE_ARG:

    default:
      easy_seccomp_set_error (ctx, "unknown argument `%s`", v->name);
      return -1;
    }

  return 0;
}

static int
generate_jump (struct easy_seccomp_ctx_s *ctx, int jump_len)
{
  struct sock_filter stmt[] = {
    BPF_JUMP(BPF_JMP|BPF_JA|BPF_K, jump_len, 0, 0),
  };
  return emit (ctx, stmt, sizeof (struct sock_filter));
}

/* generate a jump when the condition is not satisfied.  */
static int
generate_inverse_jump (struct easy_seccomp_ctx_s *ctx, int type, int value, int jump_len)
{
  int jt = 0;
  int jf = 0;
  int mask;

  switch (type)
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
      easy_seccomp_set_error (ctx, "invalid condition type %d", type);
      return -1;
    }

  struct sock_filter stmt[] = {
    BPF_JUMP(BPF_JMP|mask|BPF_K, value, jt, jf),
  };
  return emit (ctx, stmt, sizeof (struct sock_filter));
}

static int
generate_masked_condition (struct easy_seccomp_ctx_s *ctx, struct condition_s *c, int jump_len)
{
  int ret;
  int value;
  int variable;
  int mask_value;

  variable = load_variable (ctx, c->name);
  if (variable < 0)
    return variable;

  ret = read_value (ctx, c->value, variable, &value);
  if (ret < 0)
    return ret;

  ret = read_value (ctx, c->mask, variable, &mask_value);
  if (ret < 0)
    return ret;

  ret = emit_load (ctx, variable);
  if (ret < 0)
    return ret;

  emit_stmt (ctx, BPF_ALU|BPF_AND|BPF_IMM, mask_value);

  return generate_inverse_jump (ctx, c->mask_op, value, jump_len);
}

static int
generate_simple_condition (struct easy_seccomp_ctx_s *ctx, struct condition_s *c, int jump_len)
{
  int ret;
  int value;
  int variable;

  if (c->type == TYPE_MASKED_EQ)
    return generate_masked_condition (ctx, c, jump_len);

  variable = load_variable (ctx, c->name);
  if (variable < 0)
    return variable;

  ret = read_value (ctx, c->value, variable, &value);
  if (ret < 0)
    return ret;

  if (multiplexed_syscall_p (variable, value))
    {
      multiplexed_syscall_ignored_warning (ctx, c->value);
      return 0;
    }

  ret = emit_load (ctx, variable);
  if (ret < 0)
    return ret;

  return generate_inverse_jump (ctx, c->type, value, jump_len);
}

static int
linearize_and_conditions (struct easy_seccomp_ctx_s *ctx, struct condition_s *it, struct condition_s **conditions, ssize_t *so_far, ssize_t max)
{
  if (it->type == TYPE_AND)
    {
      int ret;

      ret = linearize_and_conditions (ctx, it->and_l, conditions, so_far, max);
      if (ret < 0)
        return ret;

      return linearize_and_conditions (ctx, it->and_r, conditions, so_far, max);
    }
  if (*so_far == max - 1)
    {
      easy_seccomp_set_error (ctx, "AND condition too long");
      return -1;
    }

  if (it->type == TYPE_IN_SET || it->type == TYPE_NOT_IN_SET)
    {
      easy_seccomp_set_error (ctx, "complex conditions not supported with AND");
      return -1;
    }

  conditions[*so_far] = it;
  (*so_far)++;
  return 0;
}

static int
generate_and_condition_action (struct easy_seccomp_ctx_s *ctx, struct condition_s *c, struct action_s *a)
{
  const ssize_t MAX = 8;
  struct condition_s *conditions[MAX];
  int conditions_jmp[MAX+1];
  ssize_t i, total = 0;
  int ret;

  ret = linearize_and_conditions (ctx, c, conditions, &total, MAX);
  if (ret < 0)
    return ret;

  if (total == 0)
    {
      easy_seccomp_set_error (ctx, "internal error, no AND conditions found");
      return -1;
    }

  conditions_jmp[total - 1] = 1;
  for (i = total - 2; i >= 0; i--)
    {
      int length_op = 0;

      switch (conditions[i+1]->type)
        {
        case TYPE_MASKED_EQ:
          length_op = 3;
          break;

        case TYPE_AND:
        case TYPE_EQ:
        case TYPE_NE:
        case TYPE_LT:
        case TYPE_LE:
        case TYPE_GT:
        case TYPE_GE:
          length_op = 2;
          break;

        case TYPE_IN_SET:
        case TYPE_NOT_IN_SET:
        default:
          easy_seccomp_set_error (ctx, "internal error, invalid condition type for AND");
          return -1;
        }
      conditions_jmp[i] = conditions_jmp[i+1] + length_op;
    }

  for (i = 0; i < total; i++)
    {
      ret = generate_simple_condition (ctx, conditions[i], conditions_jmp[i]);
      if (ret < 0)
        return ret;
    }

  return generate_action (ctx, a);
}

static int
cmp_size_t (const void *a, const void *b)
{
  size_t *ia = (size_t *) a;
  size_t *ib = (size_t *) b;

  if (*ia == *ib)
    return 0;

  if (*ia > *ib)
    return 1;

  return -1;
}

static size_t
find_consecutive_range_length (size_t *values, size_t size)
{
  size_t i, cur;

  if (size == 0)
    return 0;

  cur = values[0];
  for (i = 1; i < size; i++)
    {
      if (values[i] != cur + 1)
        return i;

      cur = values[i];
    }
  return size;
}

static int
generate_condition_and_action (struct easy_seccomp_ctx_s *ctx, struct condition_s *c, struct action_s *a)
{
  int ret;

  if (c == NULL)
    return 0;

  switch (c->type)
    {
    case TYPE_NOT_IN_SET:
      {
        struct head_s *set;
        size_t set_len = 0;
        int variable;
        int value;

        variable = load_variable (ctx, c->name);

        set_len = set_calculate_len (c->set);

        /* Jumps are limited to 8 bits.  This can be fixed with
           an intermediate jump.  */
        if (set_len >= 256)
          {
            easy_seccomp_set_error (ctx, "set too big");
            return -1;
          }

        emit_load (ctx, variable);

        /* This could be implemented using ranges similarly to TYPE_IN_SET,
           but for now convert to a series of disequalities.  */
        for (set = c->set; set; set = set->next)
          {
            ret = read_value (ctx, set->value, variable, &value);
            if (ret < 0)
              return ret;

            ret = generate_inverse_jump (ctx, TYPE_NE, value, set_len);
            if (ret < 0)
              return ret;

            set_len--;
          }

        generate_action (ctx, a);
      }
      break;
    case TYPE_IN_KERNEL:
      c->set = calculate_set_from_kernel_version (ctx, c->kernel);
      if (c->set == NULL)
        return -1;
        __attribute__ ((fallthrough));
    case TYPE_IN_SET:
      {
        cleanup_free size_t *remaining = NULL;
        cleanup_free size_t *values = NULL;
        size_t remaining_size = 0;
        struct head_s *set;
        size_t set_len = 0;
        size_t subset_len;
        size_t *values_it;
        int variable;
        size_t value;
        size_t i;

        variable = load_variable (ctx, c->name);
        if (variable < 0)
          return variable;

        set_len = set_calculate_len (c->set);

        values = xmalloc0 (sizeof (size_t) * set_len);
        remaining = xmalloc0 (sizeof (size_t) * set_len);

        for (set = c->set, i = 0; set; set = set->next)
          {
            int v;

            ret = read_value (ctx, set->value, variable, &v);
            if (ret < 0)
              return ret;

            values[i] = v;

            if (multiplexed_syscall_p (variable, values[i]))
              {
                multiplexed_syscall_ignored_warning (ctx, set->value);
                continue;
              }

            i++;
          }

        set_len = i;

        qsort (values, set_len, sizeof (size_t), cmp_size_t);
        values_it = values;

        ret = emit_load (ctx, variable);
        if (ret < 0)
          return ret;

        /* Jumps are limited to 8 bits.  */
        while (set_len > 0)
          {
            size_t range_len;

            range_len = find_consecutive_range_length (values_it, set_len);
            if (range_len < 3)
              {
                /* If the interval is too small, do not solve as a range.  */
                for (i = 0; i < range_len; i++)
                  remaining[remaining_size++] = values_it[i];
              }
            else
              {
                int first_value = values_it[0];
                int last_value = first_value + range_len - 1;
                struct sock_filter stmt[] =
                  {
                    BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, first_value, 0, 2),
                    BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K, last_value, 1, 0),
                  };
                ret = emit (ctx, stmt, sizeof (stmt));
                if (ret < 0)
                  return ret;
                ret = generate_action (ctx, a);
                if (ret < 0)
                  return ret;
              }

            values_it += range_len;
            set_len -= range_len;
          }

        set_len = remaining_size;
        values_it = remaining;

        /* Jumps are limited to 8 bits.  */
        while (set_len > 0)
          {
            subset_len = min (set_len, 255);
            set_len -= subset_len;

            for (i = 0; i < subset_len; i++)
              {
                value = *(values_it++);
                ret = generate_inverse_jump (ctx, TYPE_NE, value, subset_len - i);
                if (ret < 0)
                  return ret;
              }
            ret = generate_jump (ctx, 1);
            if (ret < 0)
              return ret;

            ret = generate_action (ctx, a);
            if (ret < 0)
              return ret;
          }
      }
      break;

    case TYPE_AND:
      ret = generate_and_condition_action (ctx, c, a);
      if (ret < 0)
        return ret;
      break;

    case TYPE_EQ:
    case TYPE_NE:
    case TYPE_LT:
    case TYPE_LE:
    case TYPE_GT:
    case TYPE_GE:
      ret = generate_simple_condition (ctx, c, 1);
      if (ret < 0)
        return ret;

      ret = generate_action (ctx, a);
      if (ret < 0)
        return ret;
      break;

    case TYPE_MASKED_EQ:
      ret = generate_masked_condition (ctx, c, 1);
      if (ret < 0)
        return ret;

      ret = generate_action (ctx, a);
      if (ret < 0)
        return ret;
      break;

    default:
      easy_seccomp_set_error (ctx, "invalid condition type %d", c->type);
      return -1;
    }
  return 0;
}

static struct rule_s *
skip_directive (struct easy_seccomp_ctx_s *ctx, struct rule_s *it)
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
    easy_seccomp_set_error (ctx, "directive not ended");

  return it;
}

int
easy_seccomp_run (struct easy_seccomp_ctx_s *ctx)
{
  struct rule_s *it;
  int directive_recursion = 0;

  for (it = ctx->rules; it; it = it->next)
    {
      if (it->directive_name)
        {
          int ifdef = 0;

          ifdef = STREQ (it->directive_name, "ifdef");
          if (ifdef || STREQ (it->directive_name, "ifndef"))
            {
              if (it->directive_value == NULL)
                easy_seccomp_set_error (ctx, "invalid directive `#%s`", it->directive_name);

              /* Check if the directive value is set.  */
              if (ifdef == is_defined (ctx, it->directive_value))
                directive_recursion++;
              else
                {
                  it = skip_directive (ctx, it);
                  if (it == NULL)
                    return -1;
                }
            }
          else if (STREQ (it->directive_name, "endif"))
            {
              if (directive_recursion == 0)
                {
                  easy_seccomp_set_error (ctx, "invalid directive `#%s`", it->directive_name);
                  return -1;
                }

              directive_recursion--;
            }
          else
            {
              easy_seccomp_set_error (ctx, "unknown directive `#%s`", it->directive_name);
              return -1;
            }

          continue;
        }

      if (it->condition)
        generate_condition_and_action (ctx, it->condition, it->action);
      else
        generate_action (ctx, it->action);
    }

  return 0;
}

int
easy_seccomp_compile (struct easy_seccomp_ctx_s *ctx, FILE *in, FILE *out)
{
  int ret;
  yyscan_t scanner;

  ret = yylex_init_extra (ctx, &scanner);
  if (ret < 0)
    {
      easy_seccomp_set_error (ctx, "cannot initialize scanner");
      return -1;
    }

  yyset_in (in, scanner);

  ret = yyparse (scanner, ctx);
  if (ret < 0)
    {
      yylex_destroy (scanner);
      return ret;
    }

  ctx->out = out;

  ret = easy_seccomp_run (ctx);
  if (ret < 0 || ctx->error != NULL)
    {
      yylex_destroy (scanner);
      return -1;
    }

  ret = yylex_destroy (scanner);
  if (ret < 0)
    {
      easy_seccomp_set_error (ctx, "cannot destroy scanner");
      return -1;
    }
  return 0;
}
