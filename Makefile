LIBFILES=src/bip32.c src/bip39.c

build-wallyutil:
		gcc -Iinclude -o wallyutil src/wallyutil.c $(LIBFILES) -lwallycore

build-test:
		gcc -Iinclude -o test src/test.c $(LIBFILES) -lwallycore

build: build-test build-wallyutil
