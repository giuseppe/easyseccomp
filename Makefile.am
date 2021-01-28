bin_PROGRAMS = easyseccomp sim

easyseccomp_SOURCES = src/generator.c src/types.c src/parser.y src/lexer.l
sim_SOURCES = src/sim/sim.c src/sim/bpf_filter.c

AM_YFLAGS = -d
easyseccomp_CFLAGS = -I $(abs_srcdir)/src

lexer.o: parser.o

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh

TESTS_ENVIRONMENT = PATH=$(PATH):$(abs_builddir)
TESTS = tests/test_simple.bats \
	tests/test_directive.bats \
	tests/test_range.bats \
	tests/test_arch.bats \
	tests/test_args.bats

EXTRA_DIST = COPYING README.md src/errnos.h src/generator.h src/types.h \
	src/sim/glue.h src/sim/bpf.h
