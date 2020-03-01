CC = /usr/bin/gcc
CFLAGS = -Wall -g -O3 -Wextra -Wpedantic
LDLIBS = -lcrypto

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = test/test_fast \
	test/test_fast_regression \

all: tests

tests: $(TESTS)

test: $(TESTS:=.exec)

.PHONY: clean test

test/%.exec: test/%
	@$<

test/test_fast: test/test.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/test_fast_regression: test/regression.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
