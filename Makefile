CFLAGS  += -std=c99 -Wall -O2 -D_REENTRANT -DLOG_USE_COLOR -g
LIBS    := -lpthread  -L./lib -lmicrohttpd -lgnutls

TARGET  := $(shell uname -s | tr '[A-Z]' '[a-z]' 2>/dev/null || echo unknown)

ifeq ($(TARGET), sunos)
	CFLAGS += -D_PTHREADS -D_POSIX_C_SOURCE=200112L
	LIBS   += -lsocket
else ifeq ($(TARGET), darwin)
	export MACOSX_DEPLOYMENT_TARGET = $(shell sw_vers -productVersion)
else ifeq ($(TARGET), linux)
	CFLAGS  += -D_POSIX_C_SOURCE=200112L -D_BSD_SOURCE -D_DEFAULT_SOURCE
	# LIBS    += -ldl
	LDFLAGS += -Wl,-E
else ifeq ($(TARGET), freebsd)
	CFLAGS  += -D_DECLARE_C99_LDBL_MATH
	LDFLAGS += -Wl,-E
endif

CC := gcc

all: kfhttp

kfhttp: httpd.o log.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

httpd.o: httpd.c
	$(CC) $(CFLAGS) -c -o $@ $<
log.o: log.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f kfhttp *.o
