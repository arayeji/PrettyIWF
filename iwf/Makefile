# Makefile for the IWF.
#
# Build modes:
#
#   make                       Full IWF (default): GTP + MAP-Diameter S6d/S6a
#                              + GSUP proxy + MAP SMS interworking.
#                              Requires libosmocore, libosmo-sccp, libosmo-sigtran.
#
#   make MAP_IWF_ENABLED=0 SMS_IWF_ENABLED=0
#                              GTP-only IWF (no MAP/Diameter; no libosmo deps).
#
#   make MAP_IWF_ENABLED=1     MAP + GSUP (same as default).
#   make MAP_IWF_ENABLED=1 SMS_IWF_ENABLED=1   Full (same as default).
#
# On Debian/Ubuntu:
#   sudo apt install build-essential pkg-config \
#     libosmocore-dev libosmo-sccp-dev libosmo-sigtran-dev
#
# Other targets:
#   make clean      Remove objects and binary.
#   make install    Copy iwf -> /usr/local/sbin and iwf.conf -> /etc/iwf/.
#   make uninstall  Remove the installed binary.

CC      ?= gcc
PREFIX  ?= /usr/local

CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -D_GNU_SOURCE \
           -Wall -Wextra -Wpedantic \
           -Wno-unused-parameter -Wno-pedantic \
           -Wno-unused-function -Wno-missing-field-initializers
# Newer libc headers inline atoi/strtol/strtoul/sscanf to __isoc23_* wrappers.
# If you link against an older libc (toolchain/OS mix, some containers), ld
# reports undefined references. These flags force the classic libc entry points.
CFLAGS  += -fno-builtin-atoi -fno-builtin-strtol -fno-builtin-strtoul \
           -fno-builtin-sscanf
LDFLAGS ?=
LDLIBS  ?=

# Source set: GTP IWF (always built) + MAP IWF translation units (always
# compiled; SS7 backend is conditional via -DMAP_IWF_WITH_OSMO_SIGTRAN).
SRCS    := main.c gtpv1.c gtpv2.c session.c translate.c config.c logging.c \
           subscr_cache.c \
           map_iwf.c map_session.c tcap.c map_codec.c diameter.c ss7_link.c \
           test_cmd.c
HDRS    := iwf.h gtpv1.h gtpv2.h session.h translate.h config.h logging.h \
           runtime.h uthash.h subscr_cache.h \
           map_iwf.h map_iwf_priv.h map_session.h tcap.h map_codec.h \
           diameter.h ss7_link.h test_cmd.h

BIN     := iwf

# --- Optional MAP-IWF (libosmo-sigtran) integration ----------------------
# Set MAP_IWF_ENABLED=0 on the make command line for a GTP-only stub build.
MAP_IWF_ENABLED ?= 1
ifeq ($(MAP_IWF_ENABLED),1)
  PKG_OSMO_CFLAGS := $(shell pkg-config --cflags libosmocore libosmo-sigtran libosmo-sccp 2>/dev/null)
  PKG_OSMO_LIBS   := $(shell pkg-config --libs   libosmocore libosmo-sigtran libosmo-sccp 2>/dev/null)
  CFLAGS  += -DMAP_IWF_WITH_OSMO_SIGTRAN -DGSUP_PROXY_ENABLED $(PKG_OSMO_CFLAGS)
  LDLIBS  += $(PKG_OSMO_LIBS)
  SRCS    += gsup_proto.c gsup_router.c gsup_server.c gsup_map_proxy.c
  HDRS    += gsup_proto.h gsup_router.h gsup_server.h gsup_map_proxy.h
  ifeq ($(strip $(PKG_OSMO_LIBS)),)
    $(error MAP_IWF_ENABLED=1 but pkg-config cannot find libosmocore/libosmo-sigtran/libosmo-sccp. \
            Install: sudo apt install libosmocore-dev libosmo-sccp-dev libosmo-sigtran-dev)
  endif
endif

# --- Optional MAP SMS interworking (requires MAP_IWF_ENABLED=1) ------------
SMS_IWF_ENABLED ?= 1
ifeq ($(SMS_IWF_ENABLED),1)
  ifneq ($(MAP_IWF_ENABLED),1)
    $(error SMS_IWF_ENABLED=1 requires MAP_IWF_ENABLED=1)
  endif
  CFLAGS += -DSMS_IWF_ENABLED
  SRCS   += sms_iwf.c gsup_client.c smpp_server.c
  HDRS   += sms_iwf.h gsup_client.h smpp_server.h
endif

# OBJS/DEPS must be derived after optional SRCS append (MAP SMS).
OBJS    := $(SRCS:.c=.o)
DEPS    := $(SRCS:.c=.d)

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
