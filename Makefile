CC:=clang
CFLAGS:=-Wall -pipe -O3 -ggdb3 -std=c11 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE -I/usr/local/opt/openssl@1.1/include -I/opt/homebrew/opt/openssl@1.1/include
LIBS:=-L/usr/local/opt/openssl@1.1/lib -L/opt/homebrew/opt/openssl@1.1/lib -lssl -lcrypto

SOURCES:= main.c tools.c blockchain.c

nyanblock: $(SOURCES)
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)

tosqlite: 
	$(CC) $(CFLAGS) tosqlite.c tools.c blockchain.c -o $@ $(LIBS) -lsqlite3

clean:
	rm -Rfv nyanblock nyanblock.dSYM tosqlite tosqlite.dSYM

all: nyanblock tosqlite

debug: nyanblock
	gdb $?

.PHONY: nyanblock

