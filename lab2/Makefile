CC = gcc
CFLAGS = -g -Wall -Werror

all: attack
	-tar -cvf ${USER}-handin.tar attack.c attack.h

attack: attack.c attack.h
	$(CC) $(CFLAGS) -o attack attack.c

clean: 
	rm -rf *.o
	rm -f attack