CC      ?= gcc
CFLAGS  ?= -O3 -march=native -flto
CFLAGS  += -std=gnu17 -Wall -Wextra -pthread $(shell pkg-config --cflags libcrypto zlib)
LDLIBS  += $(shell pkg-config --libs libcrypto zlib)

cryptor: cryptor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f cryptor

.PHONY: clean
