#Sample Makefile for Malloc
CC=gcc
CFLAGS=-g -O3 -fPIC -fno-builtin -lm -lpthread

all: libmalloc.so

clean:
	rm -rf libmalloc.so malloc.o

lib: libmalloc.so

libmalloc.so: malloc.o
	$(CC) $(CFLAGS) -shared -Wl,--unresolved-symbols=ignore-all $< -o $@
	
dist:
	dir=`basename $$PWD`; cd ..; tar cvf $$dir.tar ./$$dir; gzip $$dir.tar 
