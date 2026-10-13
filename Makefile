# Makefile fuer die Userspace-Bibliothek libprot
#
# Ziele:
#   make            Bibliothek bauen (build/libprot.a)
#   make test       Tests bauen und ausfuehren (tests/test_*.c)
#   make bench      Messprogramme bauen (bench/bench_*.c)
#   make clean      Build-Verzeichnis loeschen
#
# Aufrufbeispiele:
#   make CC=aarch64-linux-gnu-gcc    Cross-Compile fuer AArch64
#   make BUILD=release               Optimiert statt Debug
#   make NEON=1                      NEON-Quelle mitbauen (nur AArch64, spaeter)

CC      ?= cc
AR      ?= ar
BUILD   ?= debug

CSTD    := -std=c11
WARN    := -Wall -Wextra
INC     := -Iinclude

ifeq ($(BUILD),release)
  OPT := -O2
else
  OPT := -O0 -g
endif

CFLAGS  += $(CSTD) $(WARN) $(INC) $(OPT)

BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj
BIN_DIR   := $(BUILD_DIR)/bin
LIB       := $(BUILD_DIR)/libprot.a

# Quellen der ersten Ausbaustufe: Referenzimplementierungen ohne Hardwareunterstuetzung
SRCS := src/aes.c \
        src/chacha8.c \
        src/lfsr_serial.c \
        src/lfsr_parallel.c \
        src/prot.c

# NEON ist vorerst nicht Teil des Standard-Builds, nur auf Anforderung
ifeq ($(NEON),1)
  SRCS += src/lfsr_parallel_neon.c
endif

OBJS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))

TEST_SRCS  := $(wildcard tests/test_*.c)
TEST_BINS  := $(patsubst tests/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

BENCH_SRCS := $(wildcard bench/bench_*.c)
BENCH_BINS := $(patsubst bench/%.c,$(BIN_DIR)/%,$(BENCH_SRCS))

.PHONY: all test bench clean

all: $(LIB)

$(LIB): $(OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BIN_DIR)/%: tests/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB) -o $@

$(BIN_DIR)/%: bench/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB) -o $@

# Jeder Test ist ein eigenes Programm; ein Rueckgabewert ungleich null
# bricht make ab und laesst damit auch die CI fehlschlagen.
test: $(TEST_BINS)
	@if [ -z "$(TEST_BINS)" ]; then echo "Keine Tests gefunden (tests/test_*.c)"; fi
	@for t in $(TEST_BINS); do \
	    echo "== $$t"; \
	    $$t || exit 1; \
	done

bench: $(BENCH_BINS)

clean:
	rm -rf $(BUILD_DIR)

-include $(OBJS:.o=.d)