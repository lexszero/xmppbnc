CFLAGS += -std=c99 -Wall -Wextra -O0 -ggdb
CFLAGS += -MD -MP -MF .dep/$(@F).d

CFLAGS += $(shell pkg-config loudmouth-1.0 --cflags)
LDFLAGS += $(shell pkg-config loudmouth-1.0 --libs)

BINARY = xmppbnc
SRC = xmppbnc.c
OBJ = $(SRC:.c=.o)

all: $(BINARY)

$(BINARY): $(OBJ)

$(OBJ): %.o : %.c

-include $(shell mkdir .dep 2>/dev/null) $(wildcard .dep/*)
.PHONY:	clean

clean:
	rm -f *.o
	rm -f $(BINARY)
