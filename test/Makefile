CFLAGS=-m32 -g -Wall -W -ansi

all: hello ctordtor call_shared

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@

hello: hello.o
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

ctordtor: ctordtor.o
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

call_shared: call_shared.c shared.h libshared.so
	$(CC) $(CFLAGS) -L . -Wl,-rpath $(PWD) $< -o $@ -lshared

libshared.so: shared.c shared.h
	$(CC) $(CFLAGS) --shared -fPIC $< -o $@

clean:
	rm -f hello hello.o
	rm -f ctordtor ctordtor.o
	rm -f call_shared libshared.so
