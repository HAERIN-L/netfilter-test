LDLIBS=-lnetfilter_queue
CC=gcc

all: netfilter

netfilter.o: netfilter.c
	$(CC) -c -o $@ $<

netfilter: netfilter.o
	$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f netfilter *.o

