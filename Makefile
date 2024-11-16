SRC_DIR = src
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/objects
TARGET = dns-monitor
LIB_DIR = $(SRC_DIR)/libs

CC = gcc
CVERSTION = -std=gnu17
LDFLAGS := -lm
LPCAP := -lpcap

# Default flags for debug build
DEBUG_CFLAGS = -pedantic-errors -Wall -Wextra -Werror -g -DDEBUG
RELEASE_CFLAGS = -pedantic-errors -Wall -Wextra -Werror

ifeq ($(DEBUG),true)
	CFLAGS = $(CVERSTION) $(DEBUG_CFLAGS) -I$(LIB_DIR)
else
	CFLAGS = $(CVERSTION) $(RELEASE_CFLAGS) -I$(LIB_DIR)
endif

SRCS := $(wildcard $(SRC_DIR)/*.c)
LIB_SRCS := $(wildcard $(LIB_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
LIB_OBJS := $(patsubst $(LIB_DIR)/%.c, $(OBJ_DIR)/libs/%.o, $(LIB_SRCS))

all: $(TARGET)

$(TARGET): $(OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LPCAP)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $< $(LPCAP)

$(OBJ_DIR)/libs/%.o: $(LIB_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $< $(LPCAP)

.PHONY: clean doc

gdb: all
	gdb --args $(TARGET) $(ARGS)

pack:
	tar -cf xfeket01.tar src/* tests/* README.md Makefile manual.pdf

clean:
	rm -rf $(BUILD_DIR)/* *.tar ./dns-monitor