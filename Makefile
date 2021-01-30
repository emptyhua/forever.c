#CFLAGS=-Wall -g -I./libuv/include
CFLAGS=-O2 -I./libuv/include
#LDFLAGS=-lrt -lpthread -lnsl -ldl -lm
LDFLAGS=-lpthread

all:forever

objects=./libuv/.libs/libuv.a forever.o process.o parse_args.o toml.o

forever:$(objects)
	gcc $(CFLAGS) $(objects) -o ./forever $(LDFLAGS)

libuv/.libs/libuv.a:libuv/Makefile
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
