#   Lucas Helfstein Rocha        - 8802426

CC=gcc

ep: ep.c
	$(CC) -o epzao ep.c

clean:
	rm -f epzao ep.o
