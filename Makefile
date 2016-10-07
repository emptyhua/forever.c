CFLAGS=-Wall -g -I./libuv/include
LDFLAGS=-lrt -lpthread -lnsl -ldl -lm

all:forever

objects=forever.o parse_args.o iniparser.o dictionary.o ./libuv/.libs/libuv.a

forever:$(objects)
	gcc $(CFLAGS) $(LDFLAGS) $(objects) -o ./forever

%.o:%.c
	gcc $(CFLAGS) -c $< -o $@
