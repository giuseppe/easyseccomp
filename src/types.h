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
#ifndef TYPES_H
# define TYPES_H

# include <string.h>

# define TYPE_IN_SET 1
# define TYPE_NOT_IN_SET 2
# define TYPE_AND 3
# define TYPE_EQ 4
# define TYPE_NE 5
# define TYPE_LT 6
# define TYPE_LE 7
# define TYPE_GT 8
# define TYPE_GE 9
# define TYPE_MASKED_EQ 10
# define TYPE_IN_KERNEL 11

char *xstrdup (const char *v);
void *xmalloc0 (size_t s);

struct value_s
{
  int value;
  char *name;
};

struct head_s
{
    struct head_s *next;
    struct value_s *value;
};

struct action_s
{
  char *name;
  char *str_value;
  int int_value;
};

struct condition_s
{
  int type;
  char *name;
  char *kernel;
  int mask_op;
  struct head_s *set;
  struct value_s *mask;
  struct value_s *value;
  struct condition_s *and_l;
  struct condition_s *and_r;
};

struct rule_s
{
  struct rule_s *next;
  struct condition_s *condition;
  struct action_s *action;

  char *directive_name;
  char *directive_value;
};

struct head_s *make_set (struct value_s *value, struct head_s *next);

size_t set_calculate_len (struct head_s *set);

struct condition_s *make_in_kernel_condition (char *name, char *kernel);

struct condition_s *make_condition (int type, char *name, struct value_s *value, struct head_s *set);

struct condition_s *make_bitwise_eq_condition (char *name, struct value_s *mask, int op, struct value_s *value);

struct condition_s *make_and_condition (struct condition_s *and_l, struct condition_s *and_r);

struct rule_s *make_rule (struct condition_s *condition, struct action_s *action, struct rule_s *next);

struct rule_s *make_directive (char *name, char *value);

struct action_s *make_action (char *name, char *str_value, int int_value);

struct value_s *make_value_from_name (char *name);
struct value_s *make_value_from_int (int value);

void handle (struct rule_s *rules);

#endif
