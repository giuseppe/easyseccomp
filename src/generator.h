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

#ifndef GENERATOR_H
# define GENERATOR_H
# include "types.h"
# include <stdbool.h>
# include <stdio.h>

struct easy_seccomp_ctx_s;

struct easy_seccomp_ctx_s *easy_seccomp_make_ctx ();
void easy_seccomp_set_parser_rules (struct easy_seccomp_ctx_s *ctx, struct rule_s *rules);
void easy_seccomp_free_ctx (struct easy_seccomp_ctx_s *ctx);
const char *easy_seccomp_get_last_error (struct easy_seccomp_ctx_s *ctx);
void easy_seccomp_set_error (struct easy_seccomp_ctx_s *ctx, const char *fmt, ...);
void easy_seccomp_define (struct easy_seccomp_ctx_s *ctx, const char *v);

bool easy_seccomp_get_verbose (struct easy_seccomp_ctx_s *ctx);
void easy_seccomp_set_verbose (struct easy_seccomp_ctx_s *ctx, bool verbose);

int easy_seccomp_compile (struct easy_seccomp_ctx_s *ctx, FILE *in, FILE *out);

#endif
