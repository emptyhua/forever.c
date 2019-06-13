CFLAGS=-Wall -g -I./libuv/include
LDFLAGS=-lrt -lpthread -lnsl -ldl -lm

all:forever

objects=forever.o process.o parse_args.o toml.o ./libuv/.libs/libuv.a

forever:$(objects)
	gcc $(CFLAGS) $(objects) -o ./forever $(LDFLAGS)

%.o:%.c
	gcc $(CFLAGS) -c $< -o $@
