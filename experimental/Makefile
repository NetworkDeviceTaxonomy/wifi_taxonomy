GPERF ?= gperf

all: wifitaxonomydb.c

wifitaxonomydb.c: wifitaxonomydb.gperf
	$(GPERF) -L ANSI-C --initial-asso=2048 --jump=19 --size-multiple=3 wifitaxonomydb.gperf
