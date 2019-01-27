#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>
#include <wally_bip39.h>
#include <wally_bip32.h>
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int exit_error(char *msg)
{
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

void parse_xpub(struct ext_key* bip32key) 
{
    char xpub[113];
    int len;
    
    while(1) {
  	printf("enter xpub:\n");
	len = mygetline(xpub, 113);
	if (WALLY_OK != bip32_key_from_base58(xpub, bip32key)) {
  	    printf("invalid xpub, try again:\n");
	    continue;
	}
	return;
    }
}

void parse_privkey(unsigned char* priv)
{
    size_t len;
    unsigned char tmp[64];
    while(1) {
	printf("enter priv key:\n");
	len = mygetline(priv, 64);
        if (len != EC_PRIVATE_KEY_LEN || priv[EC_PRIVATE_KEY_LEN] != '\0') {
	    printf("invalid prreturn; %zu %c, try again:\n", len, priv[EC_PRIVATE_KEY_LEN]);
	    return;
	}
	return;
    }
}

void print_hex(unsigned char* data, int len) 
{
    for (int i = 0; i < len; i++) {
	printf("%02x", data[i]);
    }
}

int cmd_validate_mnemonic(int argc, char** argv)
{
    char mnemonic[1024];
    mygetline(mnemonic, 1024);
    if (WALLY_OK != bip39_mnemonic_validate(NULL, mnemonic)) {
        return exit_error("invalid mnemonic");
    }
    return 0;
}

int cmd_multisig(int argc, char** argv)
{
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
    return 0;
}

int cmd_usage(int argc, char** argv)
{
    printf("---- walletutil ----\n");
    printf("commands: \n");
    printf(" - validate-mnemonic:\n");
    printf("   accepts a bip39 mnemonic via STDIN and\n");
    printf("   returns the 0 exit code if it is valid\n");
    printf(" - multisig <m> <n> [--sort]:\n");
    printf("   accepts a series of bip32 keys via STDIN\n");
    printf("   and computes various script and address\n");
    printf("   formats\n");
    return 0;
}

int cmd_ecmult(int argc, char** argv)
{
    size_t addr_pubkey_len = EC_PUBLIC_KEY_LEN;
    unsigned char priv[EC_PRIVATE_KEY_LEN];
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];
    unsigned char* addr_pubkey;
    if (WALLY_OK != wally_init(0)) {
	return exit_error("couldn't initialize libwally");
    }
    for (int i = 2; i < argc; i++) {
	if (0 == strcmp("-u", argv[i]) || 0 == strcmp("--uncompressed", argv[i])) {
	    addr_pubkey_len = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
	} else {
	    return exit_error("unknown flag, see usage");
	}
    }

    parse_privkey(priv);

    if (WALLY_OK != wally_ec_public_key_from_private_key(priv, EC_PRIVATE_KEY_LEN, pubkey, EC_PUBLIC_KEY_LEN)) {
	return exit_error("failed to compute public key");
    }
    addr_pubkey = malloc(addr_pubkey_len);
    if (addr_pubkey_len == EC_PUBLIC_KEY_LEN) {
	memcpy(addr_pubkey, pubkey, EC_PUBLIC_KEY_LEN);
    } else {
	if (WALLY_OK != wally_ec_public_key_decompress(pubkey, EC_PUBLIC_KEY_LEN,
			addr_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN)) {
            return exit_error("unable to compress public key");
	}
    }
    for (int i = 0; i < addr_pubkey_len; i++) {
	printf("%02x", addr_pubkey[i]);
    }
    printf("\n");
    return 0;
}
int main(int argc, char** argv)
{
    if (WALLY_OK != wally_init(0)) {
        return exit_error("couldn't init libwally");
    }

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
    if (0 == strcmp(argv[1], "validate-mnemonic")) {
	return cmd_validate_mnemonic(argc, argv);
    } else if (0 == strcmp(argv[1], "multisig")) {
	return cmd_multisig(argc, argv);
    } else if (0 == strcmp(argv[1], "-h") || 0 == strcmp(argv[1], "help")) {
	return cmd_usage(argc, argv);
    } else if (0 == strcmp(argv[1], "ecmult")) {
        return cmd_ecmult(argc, argv);
    } else {
	return exit_error("unknown command, try help (-h) for usage");
    }
    wally_cleanup(0);
    return 0;
}
