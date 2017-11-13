VPATH = ../

all:
	cd ../; make all 
	$(MAKE) Server

Server: server.o utilities.o
	gcc -std=c99 -Wall -g -Werror -pedantic-errors $^ -o $@

server.o: server.c utilities.h
	gcc -std=c99 -Wall -g -Werror -pedantic-errors -c $<

.PHONY: clean
clean:	
	rm -f *.o Server
	cd ../; make clean

