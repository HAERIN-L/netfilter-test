LDLIBS=-lnetfilter_queue
CC=gcc

all: 1m-block

1m-block.o: 1m-block.c
	$(CC) -c -o $@ $<

1m-block: 1m-block.o
	$(LINK.c) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f 1m-block *.o

