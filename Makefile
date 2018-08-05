UNAME=$(shell uname)

CFLAGS=-m32 -g -Wall -W -ansi
LDFLAGS+=-rdynamic
ifeq ($(UNAME),Linux)
	LDFLAGS+=-ldl
	LDFLAGS+=-Wl,-Ttext-segment=0x2000000
endif

all: sldr

debug : CFLAGS+=-DDEBUG_BUILD
debug : all

%.o: %.c Makefile
	$(CC) $(CFLAGS) -ansi -c $< -o $@

sldr: sldr.o
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f sldr.o sldr
