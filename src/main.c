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
  struct easy_seccomp_ctx_s *ctx = state->input;
  switch (key)
    {
    case 'd':
      arg = argp_mandatory_argument (arg, state);
      if (arg == NULL)
          argp_usage (state);
      easy_seccomp_define (ctx, arg);
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

int
main (int argc, char **argv)
{
  int ret;
  struct easy_seccomp_ctx_s *ctx;

  if (isatty (1) && getenv ("FORCE_TTY") == NULL)
    error (EXIT_FAILURE, 0, "I refuse to write to a tty.  Redirect the output");

  ctx = easy_seccomp_make_ctx ();
  if (ctx == NULL)
    error (EXIT_FAILURE, errno, "create context");

  argp_parse (&argp, argc, argv, 0, 0, ctx);

  ret = easy_seccomp_compile (ctx, stdin, stdout);
  if (ret < 0)
    {
      fprintf (stderr, "%s\n", easy_seccomp_get_last_error (ctx));
      easy_seccomp_free_ctx (ctx);
      exit (EXIT_FAILURE);
    }

  easy_seccomp_free_ctx (ctx);
  exit (EXIT_SUCCESS);
  return 0;
}
