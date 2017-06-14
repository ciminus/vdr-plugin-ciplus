#include "crypttools.h"
#include "ciplustools.h"
#include <string.h>

int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_NOT_YET_VALID) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        if (t->tm_year < 2015)
            return 1;
    }
    if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_HAS_EXPIRED)
        return 1;
    return 0;
}

static int pkcs_1_mgf1(const uint8_t *seed, unsigned long seedlen, uint8_t *mask, unsigned long masklen)
{
	unsigned long hLen, x;
	uint32_t counter;
	uint8_t *buf;

	/* get hash output size */
	hLen = 20;      /* SHA1 */

	/* allocate memory */
	buf = (uint8_t *)malloc(hLen);
	if (buf == NULL) {
		return -1;
	}

	/* start counter */
	counter = 0;

	while (masklen > 0) {
		/* handle counter */
		BYTE32(buf, counter);
		++counter;

		/* get hash of seed || counter */
		unsigned char buffer[0x18];
		memcpy(buffer, seed, seedlen);
		memcpy(buffer + 0x14, buf, 4);
		SHA1(buffer, 0x18, buf);

		/* store it */
		for (x = 0; x < hLen && masklen > 0; x++, masklen--)
			*mask++ = buf[x];
	}

	free(buf);
	return 0;
}

static int pkcs_1_pss_encode(const uint8_t *msghash, unsigned int msghashlen,
			     unsigned long saltlen, unsigned long modulus_bitlen,
			     uint8_t *out, unsigned int outlen)
{
	unsigned char *DB, *mask, *salt, *hash;
	unsigned long x, y, hLen, modulus_len;
	int err = -1;
	unsigned char *hashbuf;
	unsigned int hashbuflen;

	hLen = 20;      /* SHA1 */
	modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

	/* allocate ram for DB/mask/salt/hash of size modulus_len */
	DB = (unsigned char *)malloc(modulus_len);
	mask = (unsigned char *)malloc(modulus_len);
	salt = (unsigned char *)malloc(modulus_len);
	hash = (unsigned char *)malloc(modulus_len);

	hashbuflen = 8 + msghashlen + saltlen;
	hashbuf = (unsigned char *)malloc(hashbuflen);

	if (!(DB && mask && salt && hash && hashbuf)) {
		goto LBL_ERR;
	}

	/* generate random salt */
	if (saltlen > 0) {
		if (get_random(salt, saltlen) != (long)saltlen) {
			goto LBL_ERR;
		}
	}

	/* M = (eight) 0x00 || msghash || salt, hash = H(M) */
	memset(hashbuf, 0, 8);
	memcpy(hashbuf + 8, msghash, msghashlen);
	memcpy(hashbuf + 8 + msghashlen, salt, saltlen);
	SHA1(hashbuf, hashbuflen, hash);

	/* generate DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */
	x = 0;
	memset(DB + x, 0, modulus_len - saltlen - hLen - 2);
	x += modulus_len - saltlen - hLen - 2;
	DB[x++] = 0x01;
	memcpy(DB + x, salt, saltlen);
	x += saltlen;

	err = pkcs_1_mgf1(hash, hLen, mask, modulus_len - hLen - 1);
	if (err)
		goto LBL_ERR;

	/* xor against DB */
	for (y = 0; y < (modulus_len - hLen - 1); y++)
		DB[y] ^= mask[y];

	/* output is DB || hash || 0xBC */
	if (outlen < modulus_len) {
		err = -1;
		goto LBL_ERR;
	}

	/* DB len = modulus_len - hLen - 1 */
	y = 0;
	memcpy(out + y, DB, modulus_len - hLen - 1);
	y += modulus_len - hLen - 1;

	/* hash */
	memcpy(out + y, hash, hLen);
	y += hLen;

	/* 0xBC */
	out[y] = 0xBC;

	/* now clear the 8*modulus_len - modulus_bitlen most significant bits */
	out[0] &= 0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1));

	err = 0;
LBL_ERR:
	free(hashbuf);
	free(hash);
	free(salt);
	free(mask);
	free(DB);

	return err;
}

/* DH */

int dh_gen_exp(uint8_t *dest, int dest_len, uint8_t *dh_g, int dh_g_len, uint8_t *dh_p, int dh_p_len)
{
	DH *dh;
	int len;
	unsigned int gap;

	dh = DH_new();

	dh->p = BN_bin2bn(dh_p, dh_p_len, 0);
	dh->g = BN_bin2bn(dh_g, dh_g_len, 0);
	dh->flags |= DH_FLAG_NO_EXP_CONSTTIME;

	DH_generate_key(dh);

	len = BN_num_bytes(dh->priv_key);
	if (len > dest_len) {
		return -1;
	}

	gap = dest_len - len;
	memset(dest, 0, gap);
	BN_bn2bin(dh->priv_key, &dest[gap]);

	DH_free(dh);

	return 0;
}

/* dest = base ^ exp % mod */
int dh_mod_exp(uint8_t *dest, int dest_len, uint8_t *base, int base_len, uint8_t *mod, int mod_len, uint8_t *exp, int exp_len)
{
	BIGNUM *bn_dest, *bn_base, *bn_exp, *bn_mod;
	BN_CTX *ctx;
	int len;
	unsigned int gap;

	bn_base = BN_bin2bn(base, base_len, NULL);
	bn_exp = BN_bin2bn(exp, exp_len, NULL);
	bn_mod = BN_bin2bn(mod, mod_len, NULL);
	ctx = BN_CTX_new();

	bn_dest = BN_new();
	BN_mod_exp(bn_dest, bn_base, bn_exp, bn_mod, ctx);
	BN_CTX_free(ctx);


	len = BN_num_bytes(bn_dest);
	if (len > dest_len) {
		return -1;
	}

	gap = dest_len - len;
	memset(dest, 0, gap);
	BN_bn2bin(bn_dest, &dest[gap]);

	BN_free(bn_dest);
	BN_free(bn_mod);
	BN_free(bn_exp);
	BN_free(bn_base);

	return 0;
}

int dh_dhph_signature(uint8_t *out, uint8_t *nonce, uint8_t *dhph, RSA *r)
{
	unsigned char dest[302];
	uint8_t hash[20];
	unsigned char dbuf[256];

	dest[0x00] = 0x00;      /* version */
	dest[0x01] = 0x00;
	dest[0x02] = 0x08;      /* len (bits) */
	dest[0x03] = 0x01;      /* version data */

	dest[0x04] = 0x01;      /* msg_label */
	dest[0x05] = 0x00;
	dest[0x06] = 0x08;      /* len (bits) */
	dest[0x07] = 0x02;      /* message data */

	dest[0x08] = 0x02;      /* auth_nonce */
	dest[0x09] = 0x01;
	dest[0x0a] = 0x00;      /* len (bits) */
	memcpy(&dest[0x0b], nonce, 32);

	dest[0x2b] = 0x04;      /* DHPH - DH public key host */
	dest[0x2c] = 0x08;
	dest[0x2d] = 0x00;      /* len (bits) */
	memcpy(&dest[0x2e], dhph, 256);

	SHA1(dest, 0x12e, hash);

	if (pkcs_1_pss_encode(hash, 20, 20, 0x800, dbuf, sizeof(dbuf))) {;
		return -1;
	}

	RSA_private_encrypt(sizeof(dbuf), dbuf, out, r, RSA_NO_PADDING);

	return 0;
}

int aes_xcbc_mac_init(struct aes_xcbc_mac_ctx *ctx, const uint8_t *key)
{
	AES_KEY aes_key;
	int y, x;

	AES_set_encrypt_key(key, 128, &aes_key);

	for (y = 0; y < 3; y++) {
		for (x = 0; x < 16; x++)
			ctx->K[y][x] = y + 1;
		AES_ecb_encrypt(ctx->K[y], ctx->K[y], &aes_key, 1);
	}

	/* setup K1 */
	AES_set_encrypt_key(ctx->K[0], 128, &ctx->key);

	memset(ctx->IV, 0, 16);
	ctx->buflen = 0;

	return 0;
}

int aes_xcbc_mac_process(struct aes_xcbc_mac_ctx *ctx, const uint8_t *in, unsigned int len)
{
	while (len) {
		if (ctx->buflen == 16) {
			AES_ecb_encrypt(ctx->IV, ctx->IV, &ctx->key, 1);
			ctx->buflen = 0;
		}
		ctx->IV[ctx->buflen++] ^= *in++;
		--len;
	}

	return 0;
}

int aes_xcbc_mac_done(struct aes_xcbc_mac_ctx *ctx, uint8_t *out)
{
	int i;

	if (ctx->buflen == 16) {
		/* K2 */
		for (i = 0; i < 16; i++)
			ctx->IV[i] ^= ctx->K[1][i];
	} else {
		ctx->IV[ctx->buflen] ^= 0x80;
		/* K3 */
		for (i = 0; i < 16; i++)
			ctx->IV[i] ^= ctx->K[2][i];
	}

	AES_ecb_encrypt(ctx->IV, ctx->IV, &ctx->key, 1);
	memcpy(out, ctx->IV, 16);

	return 0;
}