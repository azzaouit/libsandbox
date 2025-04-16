CC=gcc
CFLAGS=-fPIC -O3 -Wall -Wextra -Werror -Iinclude
LDFLAGS=-lseccomp -shared
LIB=libsandbox.so
PREFIX=/usr/local

SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)

TEST_CFLAGS=-g -fno-omit-frame-pointer ${CFLAGS}
TEST_LDFLAGS=-Wl,-rpath,$(shell pwd) $(LIB)
TESTS=$(patsubst %.c, %, $(wildcard test/*.c))

all: build tests

build: $(OBJ)
	$(CC) -o $(LIB) $(OBJ) $(LDFLAGS)

tests: build $(TESTS)

$(TESTS): %: %.c
	$(CC) $< $(TEST_CFLAGS) -o $@ $(TEST_LDFLAGS)

src/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

install: all
	sudo cp $(LIB) $(PREFIX)/lib
	sudo cp -r include $(PREFIX)/include/sandbox

uninstall:
	sudo rm -f $(PREFIX)/lib/$(LIB)
	sudo rm -rf $(PREFIX)/include/sandbox

clean:
	rm -rf $(OBJ) $(TESTS) $(LIB)
