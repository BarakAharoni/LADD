CC = gcc
CFLAGS = -Wall -O2 -fstack-protector-strong -fvisibility=hidden -D_FORTIFY_SOURCE=2 -fPIE -fstack-clash-protection
LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

TEST_PROGRAM = runner

LIB_OBJ = ladd.o
TEST_OBJ = runner.o
SRC_LIB = ladd.c
SRC_TEST = runner.c

all: $(TEST_PROGRAM)

# Compile ladd.c to object
$(LIB_OBJ): $(SRC_LIB)
	$(CC) $(CFLAGS) -c $< -o $@
	strip --strip-unneeded $@

# Compile runner.c to object
$(TEST_OBJ): $(SRC_TEST)
	$(CC) $(CFLAGS) -c $< -o $@
	strip --strip-unneeded $@

# Link objects together into final runner
$(TEST_PROGRAM): $(LIB_OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@
	strip -s $@

clean:
	rm -f $(LIB_OBJ) $(TEST_OBJ) $(TEST_PROGRAM)

.PHONY: all clean
