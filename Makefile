PYTHON?=python

all: build

test: wifi_signature
	set -e; \
	for d in $(wildcard tests/*_test.py); do \
		PYTHONPATH=./taxonomy $(PYTHON) $$d; \
	done
	PYTHONPATH=./taxonomy $(PYTHON) ./pcaptest.py

PREFIX=/usr

build:
	cd ./taxonomy && $(HOSTDIR)/usr/bin/python setup.py build

install:
	cd ./taxonomy && $(HOSTDIR)/usr/bin/python setup.py install --prefix=$(DESTDIR)$(PREFIX)

install-libs:
	@echo "No libs to install."

CC:=$(CROSS_COMPILE)gcc
CPP:=$(CROSS_COMPILE)g++
LD:=$(CROSS_COMPILE)ld
AR:=$(CROSS_COMPILE)ar
RANLIB:=$(CROSS_COMPILE)ranlib
STRIP:=$(CROSS_COMPILE)strip
BINDIR=$(DESTDIR)/bin

CFLAGS += -g -Os -Wall -Werror $(EXTRACFLAGS)
LDFLAGS += $(EXTRALDFLAGS)

SRCS = wifi_signature.c
INCS =

wifi_signature: $(SRCS) $(INCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) -lpcap

clean:
	rm -f wifi_signature *.o
