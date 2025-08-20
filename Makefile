CC ?= gcc
CFLAGS ?= -O2 -fPIC -Wall -Wextra
LDFLAGS ?=
SEC_DIR ?= /usr/lib/security

all: pam_pinlock.so pinlockctl

pam_pinlock.so: pam_pinlock.c
	$(CC) $(CFLAGS) -shared -o $@ $< -lpam -largon2

pinlockctl: pinlockctl.c
	$(CC) -O2 -Wall -Wextra -o $@ $< -largon2

install: all
	sudo install -D -m 0644 pam_pinlock.so $(SEC_DIR)/pam_pinlock.so
	sudo install -D -m 0755 pinlockctl /usr/local/bin/pinlockctl
	sudo install -d -m 0700 /etc/pinlock

clean:
	rm -f pam_pinlock.so pinlockctl
