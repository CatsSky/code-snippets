PROGRAM		= sha256.out
OBJS		= sha256.o
SRCS		= sha256.cpp
CC			= g++
CPPFLAGS	= -O2 -Wall -std=c++20


all:			$(PROGRAM)

.c.o:
				$(CC) -c $(CFLAGS) -o $@ $<

.cpp.o:
				$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

$(PROGRAM):		$(OBJS)
				$(CC) $(CPPFLAGS) $(OBJS) -o $@

clean:
				rm -f $(OBJS)

test:			$(PROGRAM)
				./test.sh