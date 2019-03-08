CC:=clang
CFLAGS:=-Wall -pipe -O3 -ggdb3
LIBS:=-lssl -lcrypto

SOURCES:= main.c tools.c

nyanblock: $(SOURCES)
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)

tosqlite: 
	$(CC) $(CFLAGS) tosqlite.c tools.c -o $@ $(LIBS) -lsqlite3

clean:
	rm main -fv

debug: nyanblock
	gdb $?

.PHONY: nyanblock
