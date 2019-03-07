CFLAGS:=-Wall -pipe -Og -ggdb3
LIBS:=-lssl -lcrypto

SOURCES:= main.c tools.c

nyanblock: $(SOURCES)
	gcc $(CFLAGS) $? -o $@ $(LIBS)

clean:
	rm main -fv

debug: nyanblock
	gdb $?

.PHONY: nyanblock
