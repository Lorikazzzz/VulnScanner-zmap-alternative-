CC = gcc
CFLAGS = -Wall -O3 -pthread -Iinclude -std=gnu99
LDFLAGS = -lpthread -lm

SRCS = src/main.c src/net.c src/utils.c src/sender.c src/receiver.c src/parsing.c src/pfring.c
OBJS = $(SRCS:.c=.o)
TARGET = scanner

ifeq ($(USE_PFRING),1)
    CFLAGS += -DUSE_PFRING
    LDFLAGS += -lpfring -lpcap
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
