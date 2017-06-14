#ifndef CRYPTTOOLS_H
#define CRYPTTOOLS_H

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>


int verify_cb(int ok, X509_STORE_CTX *ctx);
int dh_gen_exp(uint8_t *dest, int dest_len, uint8_t *dh_g, int dh_g_len, uint8_t *dh_p, int dh_p_len);
int dh_mod_exp(uint8_t *dest, int dest_len, uint8_t *base, int base_len, uint8_t *mod, int mod_len, uint8_t *exp, int exp_len);
int dh_dhph_signature(uint8_t *out, uint8_t *nonce, uint8_t *dhph, RSA *r);

struct aes_xcbc_mac_ctx {
	uint8_t K[3][16];
	uint8_t IV[16];
	AES_KEY key;
	int buflen;
};

int aes_xcbc_mac_init(struct aes_xcbc_mac_ctx *ctx, const uint8_t *key);
int aes_xcbc_mac_process(struct aes_xcbc_mac_ctx *ctx, const uint8_t *in, unsigned int len);
int aes_xcbc_mac_done(struct aes_xcbc_mac_ctx *ctx, uint8_t *out);


#endif /* CRYPTTOOLS_H */

