CC = gcc
CFLAGS = -Wall -O3 -pthread -Iinclude -std=gnu99
LDFLAGS = -lpthread -lm

SRCS = src/main.c src/net.c src/utils.c src/sender.c src/receiver.c src/parsing.c \
       src/crypto-blackrock.c src/crypto-blackrock2.c src/util-malloc.c src/util-safefunc.c src/pixie-timer.c
OBJS = $(SRCS:.c=.o)
TARGET = scanner

ifeq ($(USE_PFRING_ZC),1)
    CFLAGS += -DUSE_PFRING_ZC
    LDFLAGS += -lpfring -lpcap
    SRCS += src/send-pfring.c src/recv-pfring.c
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
