NAMESPACE:=bgp_inject

CC = gcc
CFLAGS = -std=gnu99 -Wextra -pedantic -O3

.PHONY: all libptrace_do.a bgp_inject clean
all: $(NAMESPACE)

$(NAMESPACE): libptrace_do.a
	$(CC) $(CFLAGS) -L./src/ptrace_do -o bin/$(NAMESPACE) src/bgp_inject.c -lptrace_do

libptrace_do.a:
	cd $(CURDIR)/src/ptrace_do && $(MAKE) $@

clean:
	cd $(CURDIR)/src/ptrace_do && $(MAKE) $@ clean || true
	rm -f $(CURDIR)/bin/$(NAMESPACE)
