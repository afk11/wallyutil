#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_bip39.h>
#include <wally_bip32.h>
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int exit_error(char *msg) {
    printf("ERR: %s\n", msg);
    return 1;
}

int mygetline(char line[], int maxline)
{
    int c, i;
    for (i = 0; i < maxline-1 && (c = getchar()) != EOF && c != '\n'; ++i) {
        line[i] = c;
    }
//  if (c == '\n') {
//	line[i] = c;
//	i++;
//    }
    line[i] = '\0';
    return i;
}

void parse_xpub(struct ext_key* bip32key) {
    char xpub[113];
    int len;
    
    while(1) {
  	printf("enter xpub:");
	len = mygetline(xpub, 113);
	if (WALLY_OK == bip32_key_from_base58_alloc(xpub, &bip32key)) {
	    return;
	}
	printf("invalid xpub");
    }
}
static int myCmp(const void* a, const void* b) {
    return strcmp(*(const char**)a, *(const char**)b);
}
void sort(const char* arr[], int n) {
    qsort(arr, n, sizeof(const char*), myCmp);
}
int main(int argc, char** argv) {
    if (WALLY_OK != wally_init(0)) {
        return exit_error("couldn't init libwally");
    }

    printf("----- walletutil -----\n");
    printf("argc: %d\n", argc);
    if (argc > 1) {
        printf("args:\n");
        for (int i = 1; i < argc; i++) {
            printf("[%d]: %s\n", i, argv[i]);
     	}
    }

    if (argc == 1) {
        printf("usage: \n");
        return 0;
    }
    
    printf("cmd'%s'\n",argv[1]);
    if (0 == strcmp(argv[1], "bip32-multisig")) {
  	if (argc < 3) {
	    return exit_error("m and n required as arguments\n");
	}
	int m, n;
	char *end;
	m = strtol(argv[2], &end, 10);
	if (m == 0) {
	    return exit_error("invalid value for num sigs");
	}
	n = strtol(argv[3], &end, 10);
	if (n == 0) {
	    return exit_error("invalid value for num keys");
	}
	struct ext_key* key[n];
	unsigned char* script_keys[n];
	for (int i = 0; i < n; i++) {
	    printf("please enter xpub %d\n", i);
	    parse_xpub(key[i]);
	    script_keys[i] = key[i]->pub_key;
	    //printf("public key %\n", key[i]->pub_key);
            //memcpy(script_keys[i], key[i]->pub_key, 33);
        }
	sort(script_keys, n);
	for (int i = 0; i < n; i++) {
	    printf("sorted pubkey %d\n", i);
	    for (int j = 0; j < 33; j++) {
		printf("%x", script_keys[i][j]);
	    }
	    printf("\n");
	}
	printf("multisig %d of %d\n", m, n);
    } else {
        return exit_error("usage..");
    }
    wally_cleanup(0);
    return 0;
}