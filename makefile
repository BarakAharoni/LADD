CC = gcc
CFLAGS = -fPIC -Wall

LIBRARY = libladd.so
TEST_PROGRAM = tester

LIB_SRC = ladd.c
TEST_SRC = tester.c

all: $(LIBRARY) $(TEST_PROGRAM)

$(LIBRARY): $(LIB_SRC)
	$(CC) $(CFLAGS) -shared -o $@ $^

$(TEST_PROGRAM): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $^ -ldl

clean:
	rm -f $(LIBRARY) $(TEST_PROGRAM)

.PHONY: all clean
