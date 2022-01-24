#  SPDX-License-Identifier: 0BSD
# -----------------------------------------------------------------------------

.POSIX:
.PHONY: all clean distclean

.SUFFIXES:
.SUFFIXES: .c .o

V = 0

AR = ar
CC = cc

ARFLAGS =
CPPFLAGS =
CFLAGS =
LDFLAGS =
LDLIBS =

V_MAJOR = 0
V_MINOR = 0
V_PATCH = 0
VERSION = $(V_MAJOR).$(V_MINOR).$(V_PATCH)

SONAME = libsha3.so.0

Q0 = @
Q1 =
Q = $(Q$(V))

msg0 = printf "  %-7s %s\\n"
msg1 = :
msg = $(msg$(V))
qmsg = @$(msg)

cppflags-y = -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 $(CPPFLAGS)
cflags-y = -std=c11 -O3 -Wall -Wextra -pipe $(CFLAGS)
ldflags-y = $(LDFLAGS)
ldlibs-y = $(LDLIBS)

obj-y = sha3.o

all: libsha3.a libsha3.so.$(V_MAJOR)

clean:
	$(qmsg) "CLEAN" ""
	$(Q)rm -f $(obj-y) .*.cmd

distclean: clean
	$(Q)rm -f libsha3.a libsha3.so.* compile_commands.json

compile_commands.json: $(obj-y)
	$(qmsg) "GEN" "$@"
	$(Q)printf '[\n' >"$@"
	$(Q)set -- $(obj-y); while [ -n "$${1}" ]; do \
		if [ -n "$${2}" ]; then \
			l=","; \
		else \
			l=""; \
		fi; \
		o="./$${1}"; \
		c=$$(cat "$${o%%/*}/.$${o##*/}.cmd"); \
		printf '{"directory":"%s","command":"%s","file":"%s"}%s\n' \
			"$${PWD}" "$${c}" "$${1%.o}.c" "$${l}" >>"$@"; \
		shift; \
	done
	$(Q)printf ']\n' >>"$@"

libsha3.a: $(obj-y)
	$(qmsg) "AR" "$@"
	$(Q)$(AR) -rcs $(ARFLAGS) $@ $(obj-y)

$(SONAME): $(obj-y)
	$(qmsg) "CCLD" "$@"
	$(Q)$(CC) $(cppflags-y) $(cflags-y) $(ldflags-y) -shared -Wl,-soname,$@ -o $@ $(obj-y) $(ldlibs-y)

.c.o:
	$(qmsg) "CC" "$@"
	$(Q)$(CC) $(cppflags-y) $(cflags-y) -c -o $@ $<
	$(Q)printf "%s\\n" '$(CC) $(cppflags-y) $(cflags-y) -c -o $@ $<' >"$(@D)/.$(@F).cmd"
