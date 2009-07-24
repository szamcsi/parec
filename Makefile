
include VERSION

BINS = checksums test-unit
LIBS = libparec.so
CFLAGS = -g -std=c99 -I. -Wall -W -Wmissing-prototypes
LDFLAGS = -lcrypto -L. -lparec

default: $(BINS) $(LIBS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

parec_log4c.o: parec_log4c.c parec_log4c.h
parec.o: parec.c parec.h parec_log4c.h
checksums: checksums.c $(LIBS)

libparec.so: parec.o parec_log4c.o
	$(CC) -shared -o $@ $^

default: $(BINS)

test: $(BINS)
	LD_LIBRARY_PATH=$(CURDIR) ./test-unit
	./checksums-test

clean: 
	rm -f $(BINS) $(LIBS) *.o 
	rm -rf dataset

.PHONY: default clean 
