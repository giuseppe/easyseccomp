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
#include "types.h"
#include <stdlib.h>

char *
xstrdup (char *v)
{
  char *r = strdup (v);
  if (r == NULL)
    abort ();
  return r;
}

void *
xmalloc0 (size_t s)
{
  void *r = calloc (1, s);
  if (r == NULL)
    abort ();
  return r;
}

struct head_s *
make_set (struct value_s *value, struct head_s *next)
{
  struct head_s *h = xmalloc0 (sizeof (struct head_s));
  h->value = value;
  h->next =next;
  return h;
}

struct condition_s *
make_condition (int type, char *name, struct value_s *value, struct head_s *set)
{
  struct condition_s *c = xmalloc0 (sizeof (struct condition_s));
  c->type = type;
  c->name = name;
  c->set = set;
  c->value = value;
  return c;
}

struct condition_s *
make_and_condition (struct condition_s *and_l, struct condition_s *and_r)
{
  struct condition_s *c = xmalloc0 (sizeof (struct condition_s));
  c->type = TYPE_AND;
  c->and_l = and_l;
  c->and_r = and_r;
  return c;
}


struct condition_s *
make_bitwise_eq_condition (char *name, struct value_s *mask, struct value_s *value)
{
  struct condition_s *c = xmalloc0 (sizeof (struct condition_s));
  c->type = TYPE_MASKED_EQ;
  c->mask = mask;
  c->value = value;
  return c;
}

struct rule_s *
make_rule (struct condition_s *condition, struct action_s *action, struct rule_s *next)
{
  struct rule_s *r = xmalloc0 (sizeof (struct rule_s));
  r->condition = condition;
  r->action = action;
  r->next = next;
  return r;
}

struct rule_s *
make_directive (char *name, char *value)
{
  struct rule_s *r = xmalloc0 (sizeof (struct rule_s));
  r->directive_name = name;
  r->directive_value = value;
  return r;
}

struct action_s *
make_action (char *name, char *str_value, int int_value)
{
  struct action_s *a = xmalloc0 (sizeof (struct action_s));
  a->name = name;
  a->str_value = str_value;
  a->int_value = int_value;
  return a;
}

struct value_s *
make_value_from_name (char *name)
{
  struct value_s *v = xmalloc0 (sizeof (struct value_s));
  v->name = name;
  v->value = 0;
  return v;
}

struct value_s *
make_value_from_int (int value)
{
  struct value_s *v = xmalloc0 (sizeof (struct value_s));
  v->value = value;
  return v;
}
