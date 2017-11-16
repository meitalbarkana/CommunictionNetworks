all:client.o

client.o: client.c utilities.o utilities.h
	gcc -std=c99 -Wall -g -Werror -pedantic-errors $^

clean:	
	rm -f *.o Client


