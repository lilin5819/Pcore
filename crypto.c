#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#include "core.h"
#include "msg.h"
#include "sds.h"
#include "log.h"

#define B64_ENCODE_LEN(_len)	((((_len) + 2) / 3) * 4 + 1)
#define B64_DECODE_LEN(_len)	(((_len) / 4) * 3 + 1)
// LOG_INIT("crypto");

int gen_dh_param(sds p,sds g)
{
	log_();
    DH *dh = NULL;
    dh=DH_new();
    DH_generate_parameters_ex(dh,128,DH_GENERATOR_2,NULL);   
	DH_generate_key(dh);

	sdssetlen(p,BN_bn2bin(dh->pub_key,p));
	sdssetlen(g,BN_bn2bin(dh->pub_key,g));
	DH_free(dh);
	return 0;
}

int gen_dh_keypair(sds p,sds g,sds pubkey,sds privkey)
{	
	log_();
	DH *dh = NULL;
	dh = DH_new();
	dh->p = BN_bin2bn(p,sdslen(p),NULL);
	dh->g = BN_bin2bn(g,sdslen(g),NULL);
	DH_generate_key(dh);
	sdssetlen(pubkey,BN_bn2bin(dh->pub_key,pubkey));
	sdssetlen(privkey,BN_bn2bin(dh->priv_key,privkey));
	DH_free(dh);
	return 0;
}

int gen_dh_sharekey(sds p,sds g,sds privkey,sds peer_pubkey,sds sharekey)
{
	log_();
	DH *dh = NULL;
	int sharelen = 0;
	BIGNUM *bn_peer_pubkey = NULL;
    dh = DH_new();
	dh->p = BN_bin2bn(p,sdslen(p),NULL);
	dh->g = BN_bin2bn(g,sdslen(g),NULL);
	dh->priv_key = BN_bin2bn(privkey,sdslen(privkey),NULL);

	bn_peer_pubkey = BN_bin2bn(peer_pubkey,sdslen(peer_pubkey),NULL);
	sdssetlen(sharekey,DH_compute_key(sharekey,bn_peer_pubkey,dh));
	log_mem(sharekey,sdslen(sharekey));
	BN_free(bn_peer_pubkey);
	DH_free(dh);
	return 0;
}

int _do_aes_cbc_crypt(unsigned char *in, int inlen, unsigned char **out, int *outlen, unsigned char *key, int do_encrypt)
{
	int tmplen = 0;
	unsigned char *buf = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
	EVP_CIPHER_CTX ctx;

	// #if ENABLE_AES_DEBUG
	printf("%s from: ", do_encrypt ? "encrypt" : "decrypt");
	log_mem(in, inlen);
	// #endif

	/* make sure key size == 16 */

	EVP_CIPHER_CTX_init(&ctx);

	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);

	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	buf = calloc(1, inlen + 1);

	if (!buf)
	{
		log("%s: %s malloc %d failed", __func__, do_encrypt ? "encrypt" : "decrypt", inlen + 1);
		return -1;
	}

	if (EVP_CipherUpdate(&ctx, buf, outlen, in, inlen) == 0)
	{
		log("aes_128_cbc %s failed: EVP_CipherUpdate", do_encrypt ? "encrypt" : "decrypt");
		EVP_CIPHER_CTX_cleanup(&ctx);
		FREE(buf);
		return -1;
	}

	//printf("outlen = %d", *outlen);

	if (EVP_CipherFinal_ex(&ctx, buf + *outlen, &tmplen) == 0 && (tmplen > 0))
	{
		log("aes_128_cbc %s failed: EVP_CipherFinal_ex, tmplen %d", do_encrypt ? "encrypt" : "decrypt", tmplen);
		EVP_CIPHER_CTX_cleanup(&ctx);
		FREE(buf);
		return -1;
	}

	//printf("tmplen = %d", tmplen);

	*out = buf;

	*outlen += tmplen;

	// #if ENABLE_AES_DEBUG
	printf("to: ");
	log_mem(*out, *outlen);
	// #endif
	EVP_CIPHER_CTX_cleanup(&ctx);
	return *outlen;
}

// int _do_aes_ecb_crypt(unsigned char *in, int inlen, unsigned char **out, int *outlen, unsigned char *key, int do_encrypt)
// {
// 	int tmplen;
// 	unsigned char *buf = NULL;
// 	EVP_CIPHER_CTX ctx;

// 	// #if ENABLE_AES_DEBUG
// 	printf("from: ");
// 	log_mem(in, inlen);
// 	// #endif
// 	EVP_CIPHER_CTX_init(&ctx);

// 	EVP_CipherInit_ex(&ctx, EVP_aes_128_ecb(), NULL, key, NULL, do_encrypt);

// 	if (do_encrypt)
// 		buf = malloc(inlen + AES_128_BLOCK_SIZE - inlen % AES_128_BLOCK_SIZE);
// 	else
// 		buf = malloc(inlen);

// 	if (!buf)
// 	{
// 		log("%s: %s malloc %d failed", __func__, do_encrypt ? "encrypt" : "decrypt", inlen);
// 		return -1;
// 	}

// 	if (EVP_CipherUpdate(&ctx, buf, outlen, in, inlen) == 0)
// 	{
// 		log("aes_128_ecb %s failed: EVP_CipherUpdate", do_encrypt ? "encrypt" : "decrypt");
// 		EVP_CIPHER_CTX_cleanup(&ctx);
// 		FREE(buf);
// 		return -1;
// 	}

// 	//printf("outlen = %d", *outlen);

// 	if (EVP_CipherFinal_ex(&ctx, buf + *outlen, &tmplen) == 0 && (tmplen > 0))
// 	{
// 		log("aes_128_ecb %s failed: EVP_CipherFinal_ex, tmplen %d", do_encrypt ? "encrypt" : "decrypt", tmplen);
// 		EVP_CIPHER_CTX_cleanup(&ctx);
// 		FREE(buf);
// 		return -1;
// 	}
// }


sds unb64_block(sds in)
{
	sds out = sdsnewlen("",B64_DECODE_LEN(sdslen(in)));
    sdssetlen(out,EVP_DecodeBlock((unsigned char*)out, (const unsigned char*)in, sdslen(in))-2);
	return out;
}

sds b64_block(sds in)
{
	sds out = sdsnewlen("",B64_ENCODE_LEN(sdslen(in)));
    sdssetlen(out,EVP_EncodeBlock((unsigned char*)out, (const unsigned char*)in, sdslen(in)));
	return out;
}
#if 0

int main(int argc, char const *argv[])
{
    char *dh_p = "t1974ljYI1FO1UBiaB+J5w==";
    char *dh_g = "BQ==";
    // char *dh_pubkey = "dWnMjwtSDz20UsixXTQfFA==";

	sds s_p = sdsnewlen(dh_p,128);
	sds s_g = sdsnewlen(dh_g,128);
	// sds s_pubkey = sdsnewlen(dh_pubkey,128);
	sds s_pubkey = sdsnewlen("",128);
	sds s_privkey = sdsnewlen("",128);
	sds s_sharekey = sdsnewlen("",128);

	sds s_me_pubkey = sdsnewlen("",128);
	sds s_me_privkey = sdsnewlen("",128);
	sds s_me_sharekey = sdsnewlen("",128);

	log_s(s_p);
	log_s(s_g);

	log_d(sdslen(s_p));
	log_d(sdslen(s_g));
	log_d(sdslen(s_pubkey));

	sdsupdatelen(s_p);
	sdsupdatelen(s_g);
	sdsupdatelen(s_pubkey);

	log_d(sdslen(s_p));
	log_d(sdslen(s_g));
	log_d(sdslen(s_pubkey));

	log_s(s_p);
	log_s(s_g);

	s_p = unb64_block(s_p);
	s_g = unb64_block(s_g);
	// s_pubkey = decode_b64(s_pubkey);
	log_mem(s_p,sdslen(s_p));
	log_mem(s_g,sdslen(s_g));

	gen_dh_keypair(s_p,s_g,s_pubkey,s_privkey);
	gen_dh_keypair(s_p,s_g,s_me_pubkey,s_me_privkey);

	log_mem(s_pubkey,sdslen(s_pubkey));
	log_mem(s_privkey,sdslen(s_privkey));
	log_mem(s_me_pubkey,sdslen(s_me_pubkey));
	log_mem(s_me_privkey,sdslen(s_me_privkey));

	gen_dh_sharekey(s_p,s_g,s_me_privkey,s_pubkey,s_me_sharekey);
	gen_dh_sharekey(s_p,s_g,s_privkey,s_me_pubkey,s_sharekey);

	// s_p = encode_b64(s_p);
	// s_g = encode_b64(s_g);
	// s_pubkey = encode_b64(s_pubkey);
	// log_s(s_p);
	// log_s(s_g);
	// log_s(s_pubkey);
	// log_d(sdslen(s_p));
	// log_d(sdslen(s_g));
	// log_d(sdslen(s_pubkey));
	// gen_dh_pubkey(p,g,pubkey,privkey);

	return 0;
}


#endif