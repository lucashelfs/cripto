#   Lucas Helfstein Rocha        - 8802426

CC=gcc

ep: ep.c
	$(CC) -Wall -ansi -o executavel ep.c -lm

clean:
	rm -f executavel ep.o
