# Makefile fuer die Userspace-Bibliothek libprot
#
# Ziele:
#   make            Bibliothek bauen (build/<Konfiguration>/libprot.a)
#   make test       Tests bauen und ausfuehren (tests/test_*.c)
#   make bench      Messprogramme bauen (bench/bench_*.c)
#   make clean      gesamtes Verzeichnis build/ loeschen
#
# Variablen. Jede Kombination bekommt ein eigenes Unterverzeichnis in build/,
# damit nach einem Wechsel keine veralteten Objektdateien verwendet werden.
#   BUILD=debug|release            Optimierung (Standard: debug = -O0 -g, release = -O2)
#   CHACHA8_IMPL=ref|regs|merged   eSTREAM-Variante von ChaCha8 (Standard: ref)
#   SAN=1                          AddressSanitizer und UBSan einschalten
#   CC=aarch64-linux-gnu-gcc       Cross-Compile fuer AArch64
#   NEON=1                         NEON-Quelle mitbauen (nur AArch64, spaeter)
#
# Beispiele:
#   make test
#   make test SAN=1
#   make test CHACHA8_IMPL=merged BUILD=release

CC           ?= cc
AR           ?= ar
BUILD        ?= debug
CHACHA8_IMPL ?= ref
SAN          ?=

CSTD := -std=c11
WARN := -Wall -Wextra
INC  := -Iinclude

ifeq ($(BUILD),release)
  OPT := -O2
else
  OPT := -O0 -g
endif

ifeq ($(SAN),1)
  SANFLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer
  TAG_SAN  := -san
endif

CFLAGS += $(CSTD) $(WARN) $(INC) $(OPT) $(SANFLAGS)

# Der Compiler gehoert ins Verzeichnis, sonst verwendet z. B. ein Lauf mit
# CC=clang oder CC=aarch64-linux-gnu-gcc Objektdateien eines anderen Compilers.
TAG       := $(notdir $(firstword $(CC)))-$(BUILD)-$(CHACHA8_IMPL)$(TAG_SAN)
BUILD_DIR := build/$(TAG)
OBJ_DIR   := $(BUILD_DIR)/obj
BIN_DIR   := $(BUILD_DIR)/bin
LIB       := $(BUILD_DIR)/libprot.a

# Eigene Quellen: Referenzimplementierungen ohne Hardwareunterstuetzung
SRCS := src/aes.c \
        src/chacha8.c \
        src/lfsr_serial.c \
        src/lfsr_parallel.c \
        src/prot.c

# NEON ist vorerst nicht Teil des Standard-Builds, nur auf Anforderung
ifeq ($(NEON),1)
  SRCS += src/lfsr_parallel_neon.c
endif

# Fremdquellen (unveraendert uebernommen), je Verfahren eine Variante
THIRD_SRCS := third_party/chacha8/chacha-$(CHACHA8_IMPL).c

ifneq ($(MAKECMDGOALS),clean)
  ifeq ($(wildcard $(THIRD_SRCS)),)
    $(error $(THIRD_SRCS) fehlt. Gueltige Werte fuer CHACHA8_IMPL: ref, regs, merged)
  endif
endif

# Die Fremdquellen erzeugen mit -Wextra Warnungen, die den Code nicht betreffen
# (Vorzeichenvergleich, ungenutzter Parameter, maybe-uninitialized,
# Zeichenkette ohne Nullbyte bei sigma/tau). Sie werden nur fuer diese Dateien
# abgeschaltet, nicht fuer die eigenen Quellen. Compilerspezifische Optionen
# werden nur gesetzt, wenn der Compiler die zugehoerige Warnung kennt.
cc_wno = $(shell $(CC) -Werror -W$(1) -E -x c /dev/null >/dev/null 2>&1 && echo -Wno-$(1))

VENDOR_INC := -Ithird_party/chacha8
VENDOR_WNO := -Wno-sign-compare -Wno-unused-parameter \
              $(call cc_wno,maybe-uninitialized) \
              $(call cc_wno,unterminated-string-initialization)

OBJS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS)) \
        $(patsubst third_party/%.c,$(OBJ_DIR)/third_party/%.o,$(THIRD_SRCS))

TEST_SRCS  := $(wildcard tests/test_*.c)
TEST_BINS  := $(patsubst tests/%.c,$(BIN_DIR)/%,$(TEST_SRCS))
TEST_HDRS  := $(wildcard tests/*.h tests/vectors/*.h)

BENCH_SRCS := $(wildcard bench/bench_*.c)
BENCH_BINS := $(patsubst bench/%.c,$(BIN_DIR)/%,$(BENCH_SRCS))

.PHONY: all test bench clean

all: $(LIB)

$(LIB): $(OBJS)
	@mkdir -p $(dir $@)
	rm -f $@
	$(AR) rcs $@ $^

# Der ChaCha8-Adapter bindet ecrypt-sync.h ein und braucht deshalb den
# Include-Pfad der Fremdquellen (ohne deren Warnungsausnahmen).
$(OBJ_DIR)/chacha8.o: CFLAGS += $(VENDOR_INC)

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/third_party/%.o: third_party/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(VENDOR_INC) $(VENDOR_WNO) -MMD -MP -c $< -o $@

$(BIN_DIR)/%: tests/%.c $(TEST_HDRS) $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(VENDOR_INC) $< $(LIB) -o $@

# Messprogramme brauchen clock_gettime; unter -std=c11 ist es ohne dieses Makro nicht deklariert.
$(BIN_DIR)/%: bench/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -D_POSIX_C_SOURCE=200809L $(VENDOR_INC) $< $(LIB) -o $@

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
	rm -rf build

-include $(OBJS:.o=.d)
