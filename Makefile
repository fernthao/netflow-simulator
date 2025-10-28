CC=gcc
CXX=g++
LD=g++
CFLAGS=-Wall -Werror -g
LDFLAGS=$(CFLAGS) 

TARGETS=proj3

all: $(TARGETS)

proj3: proj3.o
	$(LD) $(LDFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.cc
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGETS)
