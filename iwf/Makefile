# Makefile for the IWF.
#
# Build modes:
#
#   make                       Full IWF (default): GTP + MAP-Diameter S6d/S6a
#                              + GSUP proxy + MAP SMS interworking.
#                              Uses ../third_party/libosmo-sigtran when present
#                              (custom Huawei-NA tree). Host still needs
#                              libosmocore + libosmo-netif + libsctp.
#
#   make MAP_IWF_ENABLED=0 SMS_IWF_ENABLED=0
#                              GTP-only IWF (no MAP/Diameter; no libosmo deps).
#
#   make MAP_IWF_ENABLED=1     MAP + GSUP (same as default).
#   make MAP_IWF_ENABLED=1 SMS_IWF_ENABLED=1   Full (same as default).
#   make USE_SYSTEM_OSMO=1     Ignore the in-tree libosmo-sigtran; use distro
#                              libosmocore / libosmo-sigtran / libosmo-sccp.
#
# On Debian/Ubuntu (in-tree SIGTRAN):
#   sudo apt install build-essential pkg-config autoconf automake libtool \
#     libsctp-dev libosmocore-dev libosmo-netif-dev
#
# Other targets:
#   make clean         Remove IWF objects and binary.
#   make clean-vendor  Remove third_party build/prefix.
#   make install       Copy iwf -> /usr/local/sbin and iwf.conf -> /etc/iwf/.
#   make uninstall     Remove the installed binary.

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
# res_ninit/res_nquery/ns_parserr for PGW NAPTR discovery (pgw_dns.c).
LDLIBS  += -lresolv

# Source set: GTP IWF (always built) + MAP IWF translation units (always
# compiled; SS7 backend is conditional via -DMAP_IWF_WITH_OSMO_SIGTRAN).
SRCS    := main.c gtpv1.c gtpv2.c session.c translate.c config.c config_reload.c logging.c \
           subscr_cache.c pgw_dns.c imsi_trace.c gtp_trace.c metrics_http.c \
           map_iwf.c map_session.c tcap.c map_codec.c diameter.c ss7_link.c \
           test_cmd.c msrn_pool.c sip_iwf.c isup_codec.c isup_cic.c isup_call.c \
           in_iwf.c
HDRS    := iwf.h gtpv1.h gtpv2.h session.h translate.h config.h logging.h \
           runtime.h uthash.h subscr_cache.h pgw_dns.h imsi_trace.h gtp_trace.h metrics_http.h \
           map_iwf.h map_iwf_priv.h map_session.h tcap.h map_codec.h \
           diameter.h ss7_link.h test_cmd.h msrn_pool.h sip_iwf.h \
           isup_codec.h isup_cic.h isup_call.h in_iwf.h

BIN     := iwf

# --- Optional MAP-IWF (libosmo-sigtran) integration ----------------------
# Set MAP_IWF_ENABLED=0 on the make command line for a GTP-only stub build.
MAP_IWF_ENABLED ?= 1
USE_SYSTEM_OSMO ?= 0
VENDOR_ROOT     := $(abspath $(CURDIR)/../third_party)
VENDOR_SIGTRAN  := $(VENDOR_ROOT)/libosmo-sigtran
VENDOR_PREFIX   := $(VENDOR_ROOT)/prefix
USE_VENDOR_SIGTRAN := $(if $(wildcard $(VENDOR_SIGTRAN)/include/osmocom/sigtran/osmo_ss7.h),1,0)
ifeq ($(USE_SYSTEM_OSMO),1)
  USE_VENDOR_SIGTRAN := 0
endif
VENDOR_PC_PATH := $(VENDOR_PREFIX)/lib/pkgconfig:$(VENDOR_PREFIX)/lib/x86_64-linux-gnu/pkgconfig

ifeq ($(MAP_IWF_ENABLED),1)
  ifeq ($(USE_VENDOR_SIGTRAN),1)
    PKG_OSMO_CFLAGS := $(shell PKG_CONFIG_PATH="$(VENDOR_PC_PATH):$(PKG_CONFIG_PATH)" pkg-config --cflags libosmocore libosmo-sigtran 2>/dev/null)
    PKG_OSMO_LIBS   := $(shell PKG_CONFIG_PATH="$(VENDOR_PC_PATH):$(PKG_CONFIG_PATH)" pkg-config --libs   libosmocore libosmo-sigtran 2>/dev/null)
    VENDOR_LIBDIR   := $(shell PKG_CONFIG_PATH="$(VENDOR_PC_PATH):$(PKG_CONFIG_PATH)" pkg-config --variable=libdir libosmo-sigtran 2>/dev/null)
    ifneq ($(strip $(VENDOR_LIBDIR)),)
      LDFLAGS += -Wl,-rpath,$(VENDOR_LIBDIR)
    endif
  else
    PKG_OSMO_CFLAGS := $(shell pkg-config --cflags libosmocore libosmo-sigtran libosmo-sccp 2>/dev/null)
    PKG_OSMO_LIBS   := $(shell pkg-config --libs   libosmocore libosmo-sigtran libosmo-sccp 2>/dev/null)
    ifeq ($(strip $(PKG_OSMO_LIBS)),)
      $(error MAP_IWF_ENABLED=1 but pkg-config cannot find libosmocore/libosmo-sigtran/libosmo-sccp. \
              Build the in-tree tree (make -C ../third_party) or install distro -dev packages.)
    endif
  endif
  CFLAGS  += -DMAP_IWF_WITH_OSMO_SIGTRAN -DGSUP_PROXY_ENABLED $(PKG_OSMO_CFLAGS)
  LDLIBS  += $(PKG_OSMO_LIBS)
  SRCS    += gsup_proto.c gsup_router.c gsup_server.c gsup_map_proxy.c ussd_iwf.c msisdn_db.c
  HDRS    += gsup_proto.h gsup_router.h gsup_server.h gsup_map_proxy.h ussd_iwf.h msisdn_db.h
endif

# --- Optional MongoDB MSISDN->IMSI lookup (SRI fallback) --------------------
# Auto-enabled when libmongoc-dev is installed; MONGO_ENABLED=0 to force off.
MONGO_ENABLED ?= 1
ifeq ($(MAP_IWF_ENABLED)$(MONGO_ENABLED),11)
  PKG_MONGOC_CFLAGS := $(shell pkg-config --cflags libmongoc-1.0 2>/dev/null)
  PKG_MONGOC_LIBS   := $(shell pkg-config --libs   libmongoc-1.0 2>/dev/null)
  ifneq ($(strip $(PKG_MONGOC_LIBS)),)
    CFLAGS += -DIWF_WITH_MONGOC $(PKG_MONGOC_CFLAGS)
    LDLIBS += $(PKG_MONGOC_LIBS)
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

.PHONY: all clean clean-vendor install uninstall test-isup

# Recurse after building in-tree libosmo-sigtran so pkg-config sees prefix/.
all:
ifeq ($(MAP_IWF_ENABLED)$(USE_VENDOR_SIGTRAN),11)
	$(MAKE) -C $(VENDOR_ROOT)
	$(MAKE) $(BIN)
else
	$(MAKE) $(BIN)
endif

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(BIN) isup_codec_test

test-isup: isup_codec_test
	./isup_codec_test

isup_codec_test: isup_codec.c isup_codec_test.c isup_codec.h
	$(CC) $(CFLAGS) -o $@ isup_codec_test.c isup_codec.c

clean-vendor:
	$(MAKE) -C $(VENDOR_ROOT) clean

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/sbin/$(BIN)
	install -d $(DESTDIR)/etc/iwf
	install -m 0644 iwf.conf $(DESTDIR)/etc/iwf/iwf.conf.example

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/$(BIN)
