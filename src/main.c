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
#include <inttypes.h>
#include <argp.h>

const char *argp_program_version = "easyseccomp";
const char *argp_program_bug_address = "<giuseppe@scrivano.org>";
static char doc[] = "easyseccomp - easily generate seccomp bpf";
static char args_doc[] = "[OPTION..]";
static struct argp_option options[] = {
  { "define", 'd', "NAME", 0, "Define a symbol (used for #if(n)def directives)", 0 },
  { "input", 'i', "FILE", 0, "Input file (default stdin)", 0 },
  { "output", 'o', "FILE", 0, "Output file (default stdout)", 0 },
  { "verbose", 'v', NULL, 0, "Enable warnings", 0 },
  { 0 }
};

static char *
argp_mandatory_argument (char *arg, struct argp_state *state)
{
  if (arg)
    return arg;
  return state->argv[state->next++];
}

struct context_s
{
  struct easy_seccomp_ctx_s *ctx;
  FILE *input;
  FILE *output;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct context_s *ctx = state->input;
  switch (key)
    {
    case 'd':
      arg = argp_mandatory_argument (arg, state);
      if (arg == NULL)
        argp_usage (state);
      easy_seccomp_define (ctx->ctx, arg);
      break;

    case 'v':
      easy_seccomp_set_verbose (ctx->ctx, true);
      break;

    case 'i':
      arg = argp_mandatory_argument (arg, state);
      if (arg == NULL)
        argp_usage (state);
      ctx->input = fopen (arg, "r");
      if (ctx->input == NULL)
        {
          fprintf (stderr, "cannot open: %s: %s\n", arg, strerror (errno));
          exit (EXIT_FAILURE);
        }
      break;

    case 'o':
      arg = argp_mandatory_argument (arg, state);
      if (arg == NULL)
        argp_usage (state);
      ctx->output = fopen (arg, "w+");
      if (ctx->output == NULL)
        {
          fprintf (stderr, "cannot open: %s: %s\n", arg, strerror (errno));
          exit (EXIT_FAILURE);
        }
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

static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  return 0;
}

int
LLVMFuzzerTestOneInput (uint8_t *buf, size_t len)
{
  struct easy_seccomp_ctx_s *easyseccomp_ctx;
  FILE *stream;

  easyseccomp_ctx = easy_seccomp_make_ctx ();
  if (easyseccomp_ctx == NULL)
    return 0;

  stream = fmemopen (buf, len, "r");
  easy_seccomp_compile (easyseccomp_ctx, stream, stdout);

  easy_seccomp_free_ctx (easyseccomp_ctx);
  fclose (stream);
  return 0;
}

int
main (int argc, char **argv)
{
  int ret;
  struct context_s context;
  struct easy_seccomp_ctx_s *easyseccomp_ctx;

#ifdef FUZZER
  if (getenv ("EASYSECCOMP_FUZZ"))
    {
      extern void HF_ITER (uint8_t * *buf, size_t * len);
      for (;;)
        {
          size_t len;
          uint8_t *buf;

          HF_ITER (&buf, &len);

          LLVMFuzzerTestOneInput (buf, len);
        }
    }
#endif

  easyseccomp_ctx = easy_seccomp_make_ctx ();
  if (easyseccomp_ctx == NULL)
    error (EXIT_FAILURE, errno, "create context");

  context.ctx = easyseccomp_ctx;
  context.input = stdin;
  context.output = stdout;

  argp_parse (&argp, argc, argv, 0, 0, &context);

  if (isatty (fileno (context.output)) && getenv ("FORCE_TTY") == NULL)
    error (EXIT_FAILURE, 0, "I refuse to write to a tty.  Redirect the output");

  ret = easy_seccomp_compile (context.ctx, context.input, context.output);
  if (ret < 0)
    {
      fprintf (stderr, "%s\n", easy_seccomp_get_last_error (context.ctx));
      easy_seccomp_free_ctx (context.ctx);
      fclose (context.input);
      fclose (context.output);
      exit (EXIT_FAILURE);
    }

  easy_seccomp_free_ctx (context.ctx);
  fclose (context.input);
  fclose (context.output);
  exit (EXIT_SUCCESS);
  return 0;
}
