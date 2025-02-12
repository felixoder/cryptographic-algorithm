flags=-O2 -Wall -std=c99
ldflags=-lbu

.PHONY: all clean

all: clean SHA

SHA: SHA.o
	cc $(flags) $^ -o $@ $(ldflags)

SHA.o: SHA.c SHA.h
	cc $(flags) -c $<

clean:
	rm -f *.o SHA
