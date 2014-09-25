BASEURL=http://www.life-gone-hazy.com/src/respawn/
PROG=respawn
CFLAGS=-Wall

all: ${PROG}

$(PROG): $(PROG).o
	$(CC) -o $(PROG) $(PROG).o

$(PROG).static: $(PROG).o
	$(CC) -static -o ${@} $(PROG).o
	strip $@

clean:
	rm -f $(PROG)
	rm -f $(PROG).o
	rm -f $(PROG).core

fetch:
	fetch ${BASEURL}/Makefile
	fetch ${BASEURL}/respawn.c