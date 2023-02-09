#CFLAGS=-Wall -g -I./libuv/include
CFLAGS=-Wall -O2 -I./libuv/include
#LDFLAGS=-lrt -lpthread -lnsl -ldl -lm
LDFLAGS=-lpthread

all:forever

libuv=./libuv/.libs/libuv.a
objects=forever.o process.o parse_args.o toml.o logpipe.o logrotate.o config.o

forever:$(libuv) $(objects)
	gcc $(CFLAGS) $(objects) $(libuv) -o ./forever $(LDFLAGS)

$(libuv):libuv/Makefile
	cd ./libuv && make

libuv/Makefile:libuv/autogen.sh
	cd ./libuv && ./autogen.sh && ./configure

libuv/autogen.sh:
	git submodule update --init --recursive

%.o:%.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm *.o
	rm forever
