TARGETS := libtetraetee.a tests

all: $(TARGETS)

CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-security -Wno-deprecated-declarations -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS := -Wl,-z,relro,-z,now

CC = gcc
LD = $(CC)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

libtetraetee.a: etee_efuncs.o etee_efuncs_aes.o etee.o common.o
	ar rcs $@ $^

tests: tests.o libtetraetee.a
	$(LD) $(LDFLAGS) -o $@ $^ -lcrypto

clean:
	rm -f *.o *.a $(TARGETS)

.PHONY: all clean
