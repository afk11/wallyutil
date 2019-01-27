#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>
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
    line[i] = '\0';
    return i;
}

void parse_xpub(struct ext_key* bip32key) {
    char xpub[113];
    int len;
    
    while(1) {
  	printf("enter xpub:\n");
	len = mygetline(xpub, 113);
	if (WALLY_OK == bip32_key_from_base58(xpub, bip32key)) {
	    return;
	}
	printf("invalid xpub, try again:\n");
    }
}
void print_hex(unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
	printf("%02x", data[i]);
    }
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
  	if (argc < 4) {
	    return exit_error("m and n required as arguments\n");
	}
	int m, n, i, j;
	char *end;
	m = strtol(argv[2], &end, 10);
	if (m == 0) {
	    return exit_error("invalid value for num sigs");
	}
	n = strtol(argv[3], &end, 10);
	if (n == 0) {
	    return exit_error("invalid value for num keys");
	}
	int sort = 0;
	for (i = 4; i < argc; i++) {
	    if (strcmp(argv[i], "--sort") == 0) {
		sort = 1;
	    } else {
		return exit_error("unknown flag");
	    }
	}
	struct ext_key key[n];
	unsigned char* script_keys[n];
	for (i = 0; i < n; i++) {
	    printf("please enter xpub %d\n", i);
	    parse_xpub(&key[i]);
	    script_keys[i] = key[i].pub_key;
        }
	if (sort) {
   	    unsigned char* tmp;
	    for (i = 0; i < n; i++) {
	        for (j = 0; j < n; j++) {
		    if (strcmp(script_keys[i], script_keys[j]) < 0) {
		        tmp = script_keys[i];
		        script_keys[i] = script_keys[j];
		        script_keys[j] = tmp;
		    }
	        }
	    }
	}

        unsigned char* pubkey_bytes = malloc(n*EC_PUBLIC_KEY_LEN);
	for (i = 0; i < n; i++) {
	    memcpy(pubkey_bytes+(i*EC_PUBLIC_KEY_LEN), script_keys[i], EC_PUBLIC_KEY_LEN);
	}
	size_t script_len = 1 + n*(1 + EC_PUBLIC_KEY_LEN) + 2;
	size_t written;
        unsigned char script[script_len];
        unsigned char script_p2sh[WALLY_SCRIPTPUBKEY_P2SH_LEN];
        unsigned char script_p2wsh[WALLY_SCRIPTPUBKEY_P2WSH_LEN];	
        unsigned char script_p2wsh_p2sh[WALLY_SCRIPTPUBKEY_P2SH_LEN];

	if (WALLY_OK != wally_scriptpubkey_multisig_from_bytes(pubkey_bytes, n*EC_PUBLIC_KEY_LEN,
                    m, 0, script, script_len, &script_len)) {
	    return exit_error("failed to create multisig script");
	}

	if (WALLY_OK != wally_scriptpubkey_p2sh_from_bytes(script, script_len,
		    WALLY_SCRIPT_HASH160, script_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN, &written)) {
	    return exit_error("failed to create multisig-p2sh script");
	}
	
	if (WALLY_OK != wally_witness_program_from_bytes(script, script_len,
		    WALLY_SCRIPT_SHA256, script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN, &written)) {
	    return exit_error("failed to create multisig-p2wsh script");
	}

	if (WALLY_OK != wally_scriptpubkey_p2sh_from_bytes(script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN,
		    WALLY_SCRIPT_HASH160, script_p2wsh_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN, &written)) {
	    return exit_error("failed to create multisig-p2wsh-p2sh script");
	}

	printf("## multisig\n");
	print_hex(script, script_len);
        printf("\n");

	printf("## p2sh(multisig)\n");
	print_hex(script_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN);
	printf("\n");
	print_hex(script, script_len);
	printf("\n");

	printf("## p2wsh(multisig)\n");
	print_hex(script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN);
	printf("\n");
	print_hex(script, script_len);
	printf("\n");

        printf("## p2sh(p2wsh(multisig))\n");
	print_hex(script_p2wsh_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN);
	printf("\n");
	print_hex(script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN);
	printf("\n");
	print_hex(script, script_len);
	printf("\n");
    } else {
        return exit_error("usage..");
    }
    wally_cleanup(0);
    return 0;
}
