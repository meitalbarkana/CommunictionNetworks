all: utilities.o

utilities.o: utilities.c utilities.h
	gcc -std=c99 -Wall -g -Werror -pedantic-errors -c utilities.c

.PHONY: clean
clean:	
	rm -f *.o

