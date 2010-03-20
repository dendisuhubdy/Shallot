#!/bin/sh

all:
	gcc -O3 -Wall -I/usr/local/include -c onionhash.c
	gcc -O3 -Wall -L/usr/local/lib -lssl -lcrypto -o onionhash onionhash.o
clean:
	rm -f onionhash onionhash.o
