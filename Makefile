PYTHON?=python

all: build

test: pcaptest
	set -e; \
	for d in $(wildcard tests/*_test.py); do \
		PYTHONPATH=. $(PYTHON) $$d; \
	done

pcaptest: tax_signature
    PYTHONPATH=. python ./pcaptest.py

PREFIX=/usr

build:
	PYTHONPATH=$(TARGETPYTHONPATH) $(HOSTDIR)/usr/bin/python setup.py build

install:
	PYTHONPATH=$(TARGETPYTHONPATH) $(HOSTDIR)/usr/bin/python setup.py install --prefix=$(DESTDIR)$(PREFIX)
	install -D -m 755 wtax $(DESTDIR)/bin

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

SRCS = tax_signature.c
INCS =

tax_signature: $(SRCS) $(INCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) -lpcap

clean:
	rm -f tax_signature *.o
