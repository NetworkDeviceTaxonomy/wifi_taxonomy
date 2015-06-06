all: build

test:
	set -e; \
	for d in $(wildcard *_test.py); do \
		PYTHONPATH=. $(PYTHON) $$d; \
	done

PREFIX=/usr

build:
	PYTHONPATH=$(TARGETPYTHONPATH) $(HOSTDIR)/usr/bin/python setup.py build

install:
	PYTHONPATH=$(TARGETPYTHONPATH) $(HOSTDIR)/usr/bin/python setup.py install --prefix=$(DESTDIR)$(PREFIX)
	install -D -m 755 wtax $(DESTDIR)/bin
