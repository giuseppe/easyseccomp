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
#include "parser.h"
#include "types.h"
#include "generator.h"

#include <string.h>
#include <error.h>
#include <errno.h>

char *
skip_spaces (char *value)
{
  while (*value == ' ')
    value++;
  return value;
}

int
safe_atoi (char *value)
{
  int ret;
  char *endptr = NULL;

  errno = 0;
  ret = strtol (value, &endptr, 10);
  if (errno == ERANGE || *endptr != '\0')
    error (EXIT_FAILURE, 0, "invalid value `%s` specified", value);

  return ret;
}

%}

%option noyywrap

%%
KERNEL\([0-9]+(\.[0-9]+)+\)                      {yylval.str_value = xstrdup (skip_spaces (yytext)); return KERNEL;}
"//".*                                            {}
#[ ]*[A-Za-z_][A-Za-z0-9]+                        {yylval.str_value = xstrdup (skip_spaces (yytext+1)); return DIRECTIVE;}
$[A-Za-z_][A-Za-z0-9]*                            {yylval.str_value = xstrdup (yytext); return NAME;}
@[A-Za-z_][A-Za-z_0-9]*                           {yylval.str_value = xstrdup (yytext); return CONST_NAME;}
@[A-Za-z_][A-Za-z_0-9]*@[A-Za-z_][A-Za-z_0-9]*    {yylval.str_value = xstrdup (yytext); return CONST_NAME;}
[A-Za-z_][A-Z_0-9]+                               {yylval.str_value = xstrdup (yytext); return UCASE_NAME;}
[0-9]+                                            {yylval.int_value = safe_atoi (yytext); return NUM;}
&&                                                {return AND;}
not                                               {return NOT;}
in                                                {return IN;}
==                                                {return EQ;}
!=                                                {return NE;}
\<                                                {return LT;}
\<=                                               {return LE;}
>                                                 {return GT;}
>=                                                {return GE;}
&                                                 {return AND_BITWISE;}
=>                                                {return THEN;}
"("                                               {return LP;}
")"                                               {return RP;}
","                                               {return COMMA;}
\;                                                {return EOL;}
[ \t\n]+                                          {}
.                                                 {error (EXIT_FAILURE, 0, "unrecognized token");}
%%
