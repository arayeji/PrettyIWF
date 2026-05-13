# Makefile for the GTPv1-C <-> GTPv2-C IWF.
#
# Build:    make            (produces ./iwf)
# Run:      ./iwf -c iwf.conf
# Clean:    make clean
# Install:  sudo make install   (copies iwf to /usr/local/sbin)

CC      ?= gcc
PREFIX  ?= /usr/local

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE \
           -Wall -Wextra -Wpedantic \
           -Wno-unused-parameter -Wno-pedantic \
           -Wno-unused-function -Wno-missing-field-initializers
LDFLAGS ?=
LDLIBS  ?=

# uthash is header-only, vendored next to the sources.
SRCS    := main.c gtpv1.c gtpv2.c session.c translate.c config.c logging.c
OBJS    := $(SRCS:.c=.o)
DEPS    := $(SRCS:.c=.d)
HDRS    := iwf.h gtpv1.h gtpv2.h session.h translate.h config.h logging.h \
           runtime.h uthash.h

BIN     := iwf

.PHONY: all clean install uninstall

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/sbin/$(BIN)
	install -d $(DESTDIR)/etc/iwf
	install -m 0644 iwf.conf $(DESTDIR)/etc/iwf/iwf.conf.example

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(BIN)
