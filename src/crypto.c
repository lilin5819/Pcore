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
// #include "msg.h"
#include "sds.h"
#include "log.h"

#define B64_ENCODE_LEN(_len)	((((_len) + 2) / 3) * 4 + 1)
#define B64_DECODE_LEN(_len)	(((_len) / 4) * 3 + 1)

int gen_dh_param(sds p,sds g)
{
	log_();
	sdsinclen(p,16);
	sdsinclen(g,16);
	DH *dh = DH_new();
	size_t len_p = 0,len_g =0;
    DH_generate_parameters_ex(dh,128,DH_GENERATOR_5,NULL);   
	sdssetlen(p,BN_bn2bin(dh->p,p));
	sdssetlen(g,BN_bn2bin(dh->g,g));
	DH_free(dh);
	log_();
	return 0;
}

int gen_dh_keypair(sds p,sds g,sds pubkey,sds privkey)
{	
	log_();
	DH *dh = NULL;
	sdsinclen(pubkey,16);
	sdsinclen(privkey,16);
	dh = DH_new();
	ok(dh != NULL);
	dh->p = BN_bin2bn(p,sdslen(p),NULL);
	dh->g = BN_bin2bn(g,sdslen(g),NULL);
	ok(dh->p != NULL);
	ok(dh->g != NULL);
	DH_generate_key(dh);
	sdssetlen(pubkey,BN_bn2bin(dh->pub_key,pubkey));
	sdssetlen(privkey,BN_bn2bin(dh->priv_key,privkey));
	DH_free(dh);
	log_();
	return 0;
}

int gen_dh_sharekey(sds p,sds g,sds privkey,sds peer_pubkey,sds sharekey)
{
	log_();
	DH *dh = NULL;
	int sharelen = 0;
	BIGNUM *bn_peer_pubkey = NULL;
	sdsinclen(sharekey,16);
    dh = DH_new();
	dh->p = BN_bin2bn(p,sdslen(p),NULL);
	dh->g = BN_bin2bn(g,sdslen(g),NULL);
	dh->priv_key = BN_bin2bn(privkey,sdslen(privkey),NULL);
	bn_peer_pubkey = BN_bin2bn(peer_pubkey,sdslen(peer_pubkey),NULL);
	sdssetlen(sharekey,DH_compute_key(sharekey,bn_peer_pubkey,dh));
	log_mem(sharekey,sdslen(sharekey));
	BN_free(bn_peer_pubkey);
	DH_free(dh);
	log_();
	return 0;
}

sds aes128_cmd(sds in, sds key, int do_encrypt)
{
	int tmplen = 0;
	int outlen = 0;
	unsigned char *buf = NULL;
	unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
	EVP_CIPHER_CTX *ctx = NULL;

	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);

	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);

	EVP_CIPHER_CTX_set_padding(ctx, 0);
	// log_d(sdslen(in));
	// if(do_encrypt)
	// 	log_s(in);
	buf = calloc(1, sdslen(in) + 1);

	if (!buf)
	{
		logs("%s: %s malloc %d failed", __func__, do_encrypt ? "encrypt" : "decrypt", sdslen(in) + 1);
		return NULL;
	}

	if (EVP_CipherUpdate(ctx, buf, &outlen, in, sdslen(in)) == 0)
	{
		logs("aes_128_cbc %s failed: EVP_CipherUpdate", do_encrypt ? "encrypt" : "decrypt");
		EVP_CIPHER_CTX_cleanup(ctx);
		FREE(buf);
		return NULL;
	}

	if (EVP_CipherFinal_ex(ctx, buf + outlen, &tmplen) == 0 && (tmplen > 0))
	{
		logs("aes_128_cbc %s failed: EVP_CipherFinal_ex, tmplen %d", do_encrypt ? "encrypt" : "decrypt", tmplen);
		EVP_CIPHER_CTX_cleanup(ctx);
		FREE(buf);
		return NULL;
	}
	outlen += tmplen;


	// log_d(outlen);

	// printf("to: ");
	// log_mem(buf, outlen);
	sds ret_buf = sdsnewlen(buf,outlen);
	EVP_CIPHER_CTX_cleanup(ctx);
	free(buf);
	return ret_buf;
}

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
LOG_INIT("crypto");

#define log_sds_h(x)        \
    do                 \
    {                  \
        if (x != NULL) \
            log_mem(x,sdslen(x));   \
    } while (0);

int main(int argc, char const *argv[])
{
    char *dh_p = "t1974ljYI1FO1UBiaB+J5w==";
    char *dh_g = "BQ==";
    // char *dh_pubkey = "dWnMjwtSDz20UsixXTQfFA==";

	sds s_p = sdsnewlen("",128);
	sds s_g = sdsnewlen("",128);
	// sds s_pubkey = sdsnewlen(dh_pubkey,128);
	sds s_pubkey = sdsnewlen("",128);
	sds s_privkey = sdsnewlen("",128);
	sds s_sharekey = sdsnewlen("",128);

	sds s_me_pubkey = sdsnewlen("",128);
	sds s_me_privkey = sdsnewlen("",128);
	sds s_me_sharekey = sdsnewlen("",128);
	log_();
	gen_dh_param(s_p,s_g);

	// log_d(sdslen(s_p));
	// log_d(sdslen(s_g));
	// log_d(sdslen(s_pubkey));

	// sdsupdatelen(s_p);
	// sdsupdatelen(s_g);
	// sdsupdatelen(s_pubkey);

	// log_d(sdslen(s_p));
	// log_d(sdslen(s_g));
	// log_d(sdslen(s_pubkey));

	// s_p = unb64_block(s_p);
	// s_g = unb64_block(s_g);

	log_sds_h(s_p);
	log_sds_h(s_g);
	// s_pubkey = decode_b64(s_pubkey);

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