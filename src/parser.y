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
%{
#include "types.h"
#include "generator.h"

#include <unistd.h>
#include <stdio.h>
#include <error.h>
#include <stdlib.h>
#include <argp.h>


const char *argp_program_version = "easyseccomp";
const char *argp_program_bug_address = "<giuseppe@scrivano.org>";
static char doc[] = "easyseccomp - easily generate seccomp bpf";
static char args_doc[] = "[OPTION..]";
static struct argp_option options[] =
  {
    {"define", 'd', "NAME", 0, "Define a symbol (used for #if(n)def directives)", 0},
    {0}
  };

static char *
argp_mandatory_argument (char *arg, struct argp_state *state)
{
  if (arg)
    return arg;
  return state->argv[state->next++];
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'd':
      arg = argp_mandatory_argument (arg, state);
      if (arg == NULL)
          argp_usage (state);
      define (arg);
      break;

    case ARGP_KEY_ARG:
      argp_usage (state);
      break;

    case ARGP_KEY_END:
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}
 
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

int yylex (); 
int yyerror (const char *p)
{
  error (EXIT_FAILURE, 0, "%s", p);
  return -1;
}
%}

%union
 {
   int int_value;
   char *str_value;
   struct value_s *value;
   struct condition_s *condition;
   struct condition_s *and_condition;
   struct head_s *set;
   struct rule_s *rule;
   struct action_s *action;
};

%token <int_value> NUM
%token <str_value> NAME
%token <str_value> CONST_NAME
%token <str_value> UCASE_NAME
%token <str_value> DIRECTIVE
%token <str_value> KERNEL
%token THEN
%token AND
%token EQ
%token NE
%token LT
%token LE
%token GT
%token GE
%token AND_BITWISE
%token NOT
%token IN
%token EOL
%token LP
%token RP
%token COMMA

%type <set> set

%type <action> action;
%type <rule> rule;
%type <rule> directive;
%type <rule> rules;
%type <value> value;

%type <condition> complex_condition
%type <condition> condition
%type <condition> simple_condition
%type <condition> and_condition
%type <condition> in_set
%type <condition> eq
%type <condition> neq
%type <condition> lt
%type <condition> le
%type <condition> gt
%type <condition> ge
%type <condition> and_bitwise
%%

run: rules {handle ($1); exit (0);}

rules: rule rules {$1->next = $2; $$ = $1;}
| rule {$$ = $1;}

rule: complex_condition THEN action EOL { $$ = make_rule ($1, $3, NULL); }
| THEN action {$$ = make_rule (NULL, $2, NULL);}
| directive {$$ = $1;}

directive: DIRECTIVE {$$ = make_directive ($1, NULL);}
| DIRECTIVE UCASE_NAME {$$ = make_directive ($1, $2);}

complex_condition: condition {$$ = $1;}
| and_condition {$$ = $1;}

and_condition: condition AND condition {$$ = make_and_condition ($1, $3);}
| condition AND and_condition {$$ = make_and_condition ($1, $3);}

condition: simple_condition {$$ = $1;}
| LP simple_condition RP {$$ = $2;}

simple_condition: in_set {$$ = $1;}
| and_bitwise {$$ = $1;}
| eq {$$ = $1;}
| neq {$$ = $1;}
| lt {$$ = $1;}
| le {$$ = $1;}
| gt {$$ = $1;}
| ge {$$ = $1;}

and_bitwise: NAME AND_BITWISE value EQ value {$$ = make_bitwise_eq_condition ($1, $3, TYPE_EQ, $5);}
| NAME AND_BITWISE value NE value {$$ = make_bitwise_eq_condition ($1, $3, TYPE_NE, $5);}
| NAME AND_BITWISE value LT value {$$ = make_bitwise_eq_condition ($1, $3, TYPE_LT, $5);}
| NAME AND_BITWISE value LE value {$$ = make_bitwise_eq_condition ($1, $3, TYPE_LE, $5);}
| NAME AND_BITWISE value GT value {$$ = make_bitwise_eq_condition ($1, $3, TYPE_GT, $5);}
| NAME AND_BITWISE value GE value {$$ = make_bitwise_eq_condition ($1, $3, TYPE_GE, $5);}


eq: NAME EQ value {$$ = make_condition (TYPE_EQ, $1, $3, NULL);}
neq: NAME NE value {$$ = make_condition (TYPE_NE, $1, $3, NULL);}
lt: NAME LT value {$$ = make_condition (TYPE_LT, $1, $3, NULL);}
le: NAME LE value {$$ = make_condition (TYPE_LE, $1, $3, NULL);}
gt: NAME GT value {$$ = make_condition (TYPE_GT, $1, $3, NULL);}
ge: NAME GE value {$$ = make_condition (TYPE_GE, $1, $3, NULL);}

in_set: NAME IN LP set RP {$$ = make_condition (TYPE_IN_SET, $1, NULL, $4);}
| NAME NOT IN LP set RP {$$ = make_condition (TYPE_NOT_IN_SET, $1, NULL, $5);}
| NAME IN KERNEL {$$ = make_in_kernel_condition ($1, $3);}

set: value COMMA set {$$ = make_set ($1, $3);}
| value {$$ = make_set ($1, NULL);}

action: UCASE_NAME LP RP {$$ = make_action ($1, NULL, 0); }
| UCASE_NAME LP UCASE_NAME RP {$$ = make_action ($1, $3, 0); }
| UCASE_NAME LP NUM RP {$$ = make_action ($1, NULL, $3); }

value: CONST_NAME {$$ = make_value_from_name ($1);}
| NUM  { $$ = make_value_from_int ($1); }

%%

int
main (int argc, char **argv)
{
  argp_parse (&argp, argc, argv, 0, 0, NULL);

  if (isatty (1) && getenv ("FORCE_TTY") == NULL)
    error (EXIT_FAILURE, 0, "I refuse to write to a tty.  Redirect the output");

  yyparse ();
  return 0;
}
