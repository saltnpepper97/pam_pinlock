CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared
PAM_LIBS = -lpam -largon2
CTL_LIBS = -largon2

# Installation directories - auto-detect or use common defaults
PAM_MODULE_DIR := $(shell find /lib* /usr/lib* -name "pam_unix.so" -exec dirname {} \; 2>/dev/null | head -1)
ifeq ($(PAM_MODULE_DIR),)
    PAM_MODULE_DIR := /lib/x86_64-linux-gnu/security
endif

LIBDIR = $(PAM_MODULE_DIR)
BINDIR = /usr/local/bin
CONFDIR = /etc
EXAMPLEDIR = $(CONFDIR)/pinlock/examples

# Targets
all: pam_pinlock.so pinlockctl

pam_pinlock.so: pam_pinlock.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(PAM_LIBS)

pinlockctl: pinlockctl.c
	$(CC) $(CFLAGS) -o $@ $< $(CTL_LIBS)

install: all
	@echo "Installing to PAM directory: $(LIBDIR)"
	install -m 755 -d $(DESTDIR)$(LIBDIR)
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 755 -d $(DESTDIR)$(EXAMPLEDIR)
	install -m 644 pam_pinlock.so $(DESTDIR)$(LIBDIR)/
	install -m 755 pinlockctl $(DESTDIR)$(BINDIR)/
	install -m 644 examples/pinlock.conf $(DESTDIR)$(EXAMPLEDIR)/pinlock.conf
	@echo ""
	@echo "Installation complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Copy /etc/pinlock/examples/pinlock.conf to /etc/pinlock.conf and edit as needed"
	@echo "   sudo cp /etc/pinlock/examples/pinlock.conf /etc/pinlock.conf"
	@echo "2. Add the PAM module to your PAM configuration:"
	@echo "   Example for /etc/pam.d/common-auth:"
	@echo "   auth    optional    pam_pinlock.so"
	@echo "3. Set up PINs for users with: pinlockctl set username"

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/pam_pinlock.so
	rm -f $(DESTDIR)$(BINDIR)/pinlockctl
	rm -f $(DESTDIR)$(EXAMPLEDIR)/pinlock.conf
	rmdir $(DESTDIR)$(EXAMPLEDIR) 2>/dev/null || true
	rmdir $(DESTDIR)$(CONFDIR)/pinlock 2>/dev/null || true

clean:
	rm -f pam_pinlock.so pinlockctl

test: pinlockctl
	@echo "Testing pinlockctl..."
	./pinlockctl help

.PHONY: all install uninstall clean test
