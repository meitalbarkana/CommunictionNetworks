CC = gcc
COMP_FLAG = -std=c99 -Wall -g -Werror -pedantic-errors

all: clean file_server file_client

file_server: server.o utilities.o
	$(CC) $(COMP_FLAG) $^ -o $@

file_client: client.o utilities.o
	$(CC) $(COMP_FLAG) $^ -o $@

server.o: server.c server.h utilities.h
	$(CC) $(COMP_FLAG) -c $<

client.o: client.c utilities.h
	$(CC) $(COMP_FLAG) -c $<

utilities.o: utilities.c utilities.h
	$(CC) $(COMP_FLAG) -c utilities.c

.PHONY: clean
clean:	
	rm -f *.o file_server file_client

