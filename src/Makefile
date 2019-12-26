UNAME:=$(shell uname)
ifeq ($(UNAME), Linux)
CC=g++
LIBS=-lcrypto -lssl
endif
ifeq ($(UNAME), Darwin)
CC=g++-5.2.0
LIBS=
endif


IDIR =../include
ODIR=obj

CFLAGS=-Wall -std=c++14 -I$(IDIR)

_DEPS = TOTP.h
_OBJ = TOTP.o main.o

DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.cxx $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

TOTP: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core TOTP $(IDIR)/*~
