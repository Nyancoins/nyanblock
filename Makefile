CC:=clang
CFLAGS:=-Wall -pipe -Og -ggdb3
LIBS:=-lssl -lcrypto

SOURCES:= main.c tools.c

nyanblock: $(SOURCES)
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)

clean:
	rm main -fv

debug: nyanblock
	gdb $?

.PHONY: nyanblock
