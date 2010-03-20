#!/bin/sh

all:
	gcc -O3 -Wall -I/usr/local/include -c src/math.c -o src/math.o
	gcc -O3 -Wall -I/usr/local/include -c src/error.c -o src/error.o
	gcc -O3 -Wall -I/usr/local/include -c src/linux.c -o src/linux.o
	gcc -O3 -Wall -I/usr/local/include -c src/print.c -o src/print.o
	gcc -O3 -Wall -I/usr/local/include -c src/thread.c -o src/thread.o
	gcc -O3 -Wall -I/usr/local/include -c src/shallot.c -o src/shallot.o
	gcc -O3 -Wall -L/usr/local/lib -pthread -lm -lpthread -lssl -lcrypto -o shallot src/math.o src/error.o src/linux.o src/print.o src/thread.o src/shallot.o
debug:
	gcc -g -O3 -Wall -I/usr/local/include -c src/math.c -o src/math.o
	gcc -g -O3 -Wall -I/usr/local/include -c src/error.c -o src/error.o
	gcc -g -O3 -Wall -I/usr/local/include -c src/linux.c -o src/linux.o
	gcc -g -O3 -Wall -I/usr/local/include -c src/print.c -o src/print.o
	gcc -g -O3 -Wall -I/usr/local/include -c src/thread.c -o src/thread.o
	gcc -g -O3 -Wall -I/usr/local/include -c src/shallot.c -o src/shallot.o
	gcc -g -O3 -Wall -L/usr/local/lib -pthread -lm -lpthread -lssl -lcrypto -o shallot src/math.o src/error.o src/linux.o src/print.o src/thread.o src/shallot.o
clean:
	rm -f shallot src/math.o src/error.o src/linux.o src/print.o src/thread.o src/shallot.o
