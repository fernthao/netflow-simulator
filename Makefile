CC=gcc
CXX=g++
LD=g++
CFLAGS=-Wall -Werror -g
LDFLAGS=$(CFLAGS) 

TARGETS=proj3

# Object files
OBJS=main.o utils.o hashers.o packet_reader.o print_mode.o netflow_mode.o rtt_mode.o

all: $(TARGETS)

proj3: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.cc
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGETS)
