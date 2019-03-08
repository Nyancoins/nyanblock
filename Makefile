CC:=clang
CFLAGS:=-Wall -pipe -O3 -march=native -ggdb3 -std=c11 -D_POSIX_C_SOURCE
LIBS:=-lssl -lcrypto

SOURCES:= main.c tools.c

nyanblock: $(SOURCES)
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)

tosqlite: 
	$(CC) $(CFLAGS) tosqlite.c tools.c -o $@ $(LIBS) -lsqlite3

clean:
	rm nyanblock tosqlite -fv

all: nyanblock tosqlite

debug: nyanblock
	gdb $?

.PHONY: nyanblock

