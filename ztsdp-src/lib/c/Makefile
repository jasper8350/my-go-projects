CC := gcc
CFLAGS := -Wall -Werror
BINDIR := bin

all: $(BINDIR)/libgnspa.so

$(BINDIR)/libgnspa.so: gnspa.o | $(BINDIR)
	$(CC) $(LDFLAGS) -shared -o $@ $<

gnspa.o: gnspa.c gnspa.h
	$(CC) $(CFLAGS) -c -fpic $< -o $@

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f *.o $(BINDIR)/libgnspa.so
