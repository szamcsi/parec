

BINS = checksums
CFLAGS = -g -std=c99
LFLAGS = -lcrypto

%: %.c
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

default: $(BINS)

test: $(BINS)
	./checksums-test

clean: 
	rm -f $(BINS)
