CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -Werror -pedantic -Ofast
DEBUG_CFLAGS=-ggdb
LDFLAGS=

all: dc utils

debug: CFLAGS+=${DEBUG_CFLAGS}
debug: all

dc: dc.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

utils: relation rev xor bitfreq

relation: relation.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}
rev: rev.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}
xor: xor.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}
bitfreq: bitfreq.o
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

clean:
	rm *.o dc relation rev xor bitfreq