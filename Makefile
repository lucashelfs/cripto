#   Lucas Helfstein Rocha        - 8802426

CC=gcc

ep: ep.c
	$(CC) -Wall -ansi -o epzao ep.c -lm

clean:
	rm -f epzao ep.o
