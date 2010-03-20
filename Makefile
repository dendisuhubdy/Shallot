#!/bin/sh

all:
	rm -f shallot src/shallot.o
	gcc -O3 -Wall -I/usr/local/include -c src/shallot.c -o src/shallot.o
	gcc -O3 -Wall -L/usr/local/lib -pthread -lpthread -lssl -lcrypto -o shallot src/shallot.o
debug:
	rm -f shallot src/shallot.o
	gcc -O3 -g -Wall -I/usr/local/include -c src/shallot.c -o src/shallot.o
	gcc -O3 -g -Wall -L/usr/local/lib -pthread -lpthread -lssl -lcrypto -o shallot src/shallot.o
clean:
	rm -f shallot src/shallot.o
