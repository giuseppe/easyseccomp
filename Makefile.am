bin_PROGRAMS = easyseccomp

easyseccomp_SOURCES = generator.c types.c parser.y lexer.l
AM_YFLAGS = -d

lexer.o: parser.o

EXTRA_DIST = COPYING README.md errnos.h generator.h types.h
