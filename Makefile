.PHONY: run all clean

CFLAGS = -I ../../include -I include -O2 -g -Wall -Werror -m64 -ffreestanding -fno-stack-protector -std=gnu99

DIR = obj

OBJS = obj/main.o obj/loadbalancer.o obj/session.o obj/service.o obj/server.o \
       obj/nat.o obj/dnat.o obj/dr.o obj/schedule.o obj/addr_manager.o

LIBS = ../../lib/libpacketngin.a

all: $(OBJS)
	ld -melf_x86_64 -nostdlib -e main -o main $^ $(LIBS)

obj/%.o: src/%.c
	mkdir -p $(DIR)
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj
	rm -f main
	rm -f configure

run: all
	../../bin/console script
