CFLAGS:=-pipe -Og -ggdb3
LIBS:=-lssl -lcrypto

main:
	gcc $(CFLAGS) main.c tools.c -o main $(LIBS)

clean:
	rm main -fv