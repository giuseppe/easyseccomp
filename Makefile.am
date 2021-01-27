bin_PROGRAMS = easyseccomp

easyseccomp_SOURCES = src/generator.c src/types.c src/parser.y src/lexer.l
AM_YFLAGS = -d
easyseccomp_CFLAGS = -I $(abs_srcdir)/src

lexer.o: parser.o

EXTRA_DIST = COPYING README.md src/errnos.h src/generator.h src/types.h
